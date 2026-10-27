"""The HTTP API of the agent (``/v1/...``), called by the portal only.

Every request carries the bearer token of the agent and the ``X-SRE-*`` identity headers of the
web user (``sreweb.identity``); the handlers check the access rules (``access.py``) and drive
``sre`` through the runner, the registry, the answers store and the schedulers.  Long
operations stream: ``start`` answers NDJSON (one JSON object per line, the events of
``SRE/progress.py`` then a final ``result`` line), the events and the terminals are WebSockets,
like the virtual X desktop of a project (``display.py``: raw RFB bytes for noVNC).  The schema
PDF is rendered here by graphviz (``schema.pdf``, no ``sre`` call).  Save, restore and the
Kathara export are not offered on the web.
"""
import asyncio
import contextlib
import hmac
import json
import logging
import os
import secrets
import shlex
import socket
import subprocess
import time

from aiohttp import web, WSMsgType

from SRE import params
from SRE import common
from SRE.archive_summary import error_entries, exo_grade_list
from SRE.common import TranslatedText
from SRE.evaluation_table import build_evaluation_rows, header_labels, rows_to_json
from SRE.form_spec import parse_form_description, chunks_to_json

from . import access, occupancy
from .access import AccessError
from .answers import AnswersStore
from .display import DisplayManager, DisplayError, WS_DISPLAY_FAILED
from .registry import Registry, Project, EVENT_INFO, EVENT_TERMINALS
from .results import ArchiveIndex
from .rfb_filter import RfbInputFilter, RfbProtocolError
from .runner import (SreRunner, CommandError, CommandTimeout, FlavorFormNeeded, FlavorError, build_argv,
                     build_env, PHASE_PROJECT)
from .schedulers import Schedulers
from .terminals import (TerminalSession, MAX_CLIENTS_PER_SESSION, MAX_READONLY_CLIENTS_PER_SESSION,
                        PROBE_DELAY)  # noqa: F401  (PROBE_DELAY: the tests)
from ..config import AgentConfig
from ..identity import Identity, IdentityError, IDENTITY_KEY
from ..i18n import translator
from ..projectview import sanitise, schema_svg, schema_pdf, lang_priority

log = logging.getLogger('sreweb.agent')

API_PREFIX = '/v1'
AGENT_KEY = web.AppKey('agent', object)
TERMINAL_SUBPROTOCOL = 'sre-term.v1'
DISPLAY_SUBPROTOCOL = 'sre-display.v1'
DISPLAY_CHUNK = 1 << 16      # bytes read from the X server per WebSocket frame (the relay caps frames at 1 MiB)
NDJSON = 'application/x-ndjson'
#: Close codes of the terminal WebSocket.
WS_UNAUTHENTICATED = 4401
WS_FORBIDDEN = 4403
WS_NOT_FOUND = 4404
WS_LIMIT = 4409
MAX_TERMINAL_COLS, MAX_TERMINAL_ROWS = 500, 300
CLIENT_MAX_SIZE = 4 << 20        # the answers of a PUT (the portal caps them lower)
WS_HEARTBEAT = 30.0


def json_error(status: int, message: str) -> web.Response:
    return web.json_response({'error': message, 'status': status}, status=status)


OCCUPANCY_TTL = 5.0


def _uptime_seconds() -> int | None:
    try:
        with open('/proc/uptime') as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def _system_stopping() -> bool:
    """Whether systemd is shutting the system down (``systemctl is-system-running`` says
    ``stopping``); false when systemd is not there."""
    try:
        result = subprocess.run(['systemctl', 'is-system-running'], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.stdout.strip() == 'stopping'


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
                 localedirs=None, hostname: str | None = None, extra_env: dict | None = None,
                 archive_dirs: list | None = None):
        """*archive_dirs*: where the evaluation archives are (``params.archive_dirs`` by default):
        the last evaluation of each project shown to the instructors."""
        self.cfg = cfg
        self.pub_dir = pub_dir or params.sre_pub_dir
        self.projects_dir = projects_dir or params.sre_projects_dir
        self.localedirs = list(localedirs if localedirs is not None else params.locale_dirs)
        self.hostname = hostname or socket.gethostname()
        self.runner = SreRunner(cfg.sre_exe, timeouts=cfg.timeouts, max_concurrent_starts=cfg.max_concurrent_starts,
                                max_concurrent_evals=cfg.max_concurrent_evals, extra_env=extra_env)
        self.registry = Registry(self.projects_dir, poll_interval=cfg.poll_interval, state_dir=cfg.state_dir)
        self.registry.info_event = self._info_event
        # the operations log goes to the subscribers allowed to read it only
        self.registry.log_allowed = lambda project, identity: bool(
            project.debug or access.instructor_view_allowed(project.info, identity))
        self.results = ArchiveIndex(archive_dirs)
        self.displays = DisplayManager(cfg.display, registry=self.registry)
        self.answers = AnswersStore(self.registry, hostname=self.hostname, pub_dir=self.pub_dir)
        self.schedulers = Schedulers(self.registry, self.runner, exam_mode=self.exam_mode,
                                     default_idle_timeout=cfg.max_idle)
        self._labs_cache: tuple[float, list] | None = None
        self._labs_lock = asyncio.Lock()
        self._refused_clients: set = set()
        self._occupancy: tuple[float, tuple] | None = None
        self._started_at = time.monotonic()
        #: Whether the system is going down (SIGTERM at shutdown): injectable for the tests.
        self.system_stopping = _system_stopping
        self.run_command = subprocess.run

    # -- helpers --------------------------------------------------------------------------------

    def exam_mode(self) -> bool:
        return access.exam_mode_on(self.pub_dir)

    def _info_event(self, project: Project, identity: Identity) -> dict:
        return {'t': EVENT_INFO, 'project': self._view(project, identity)}

    def _view(self, project: Project, identity: Identity) -> dict:
        return sanitise(project.info, identity, exam_mode=self.exam_mode(),
                        display_enabled=self.displays.offered(project),
                        connect_all=access.is_privileged_caller(project.rln, identity))

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
        app.router.add_post(f'{p}/power/off', self.power_off)
        app.router.add_get(f'{p}/labs', self.labs_handler)
        app.router.add_get(f'{p}/projects', self.projects_list)
        app.router.add_post(f'{p}/projects', self.projects_create)
        app.router.add_get(f'{p}/projects/{{rln}}', self.project_get)
        app.router.add_delete(f'{p}/projects/{{rln}}', self.project_close)
        app.router.add_get(f'{p}/projects/{{rln}}/events', self.events_ws)
        app.router.add_get(f'{p}/projects/{{rln}}/schema.svg', self.schema)
        app.router.add_get(f'{p}/projects/{{rln}}/schema.pdf', self.schema_pdf)
        app.router.add_put(f'{p}/projects/{{rln}}/answers', self.answers_put)
        app.router.add_post(f'{p}/projects/{{rln}}/eval', self.eval_post)
        app.router.add_get(f'{p}/projects/{{rln}}/evaluation', self.evaluation_get)
        app.router.add_post(f'{p}/projects/{{rln}}/states/{{state}}', self.state_post)
        app.router.add_get(f'{p}/projects/{{rln}}/terminals/{{device}}', self.terminal_ws)
        app.router.add_get(f'{p}/projects/{{rln}}/display', self.display_get)
        app.router.add_post(f'{p}/projects/{{rln}}/display', self.display_post)
        app.router.add_get(f'{p}/projects/{{rln}}/display/ws', self.display_ws)
        app.router.add_get(f'{p}/projects/{{rln}}/log', self.log_get)
        app.router.add_post(f'{p}/projects/{{rln}}/touch', self.touch)
        app.on_startup.append(self._on_startup)
        app.on_shutdown.append(self._on_shutdown)
        return app

    async def _on_startup(self, app):
        self.displays.prepare()
        await self.registry.tick()
        self.registry.start()

    async def _on_shutdown(self, app):
        await self.close_managed_projects()
        await self.registry.stop()
        await self.displays.stop_all()

    async def close_managed_projects(self):
        """On the stop of the agent: the projects it created are evaluated (when their lab asks)
        and stopped before the machine halts, so that the last evaluation is archived; only when
        the system is going down, unless ``close_projects_on_stop`` says always / never."""
        mode = self.cfg.close_projects_on_stop
        if mode == 'never' or (mode == 'shutdown' and not self.system_stopping()):
            return
        projects = [p for p in self.registry.projects.values() if p.managed and not p.closing]
        if not projects:
            return
        log.info("stopping: closing %d managed project(s)", len(projects))
        try:
            async with asyncio.timeout(self.cfg.shutdown_timeout):
                await asyncio.gather(*(self.schedulers.close_project(p) for p in projects), return_exceptions=True)
        except TimeoutError:
            log.error("stopping: %d project(s) not closed within %.0f s", sum(1 for p in projects if p.closing),
                      self.cfg.shutdown_timeout)

    # -- occupancy ------------------------------------------------------------------------------

    def occupied(self) -> tuple:
        """``(occupied, reasons)``, computed at most every OCCUPANCY_TTL seconds."""
        now = time.monotonic()
        if self._occupancy is not None and now - self._occupancy[0] < OCCUPANCY_TTL:
            return self._occupancy[1]
        local = sum(1 for p in self.registry.projects.values() if not p.managed)
        result = occupancy.occupancy(self.cfg.occupied_check, local, self.run_command)
        self._occupancy = (now, result)
        return result

    # -- middlewares ----------------------------------------------------------------------------

    @web.middleware
    async def auth_middleware(self, request, handler):
        if not access.client_allowed(request.remote, self.cfg.allowed_clients):
            if request.remote not in self._refused_clients:
                self._refused_clients.add(request.remote)
                log.warning("client %s refused: not in allowed_clients", request.remote)
            return json_error(403, "client address not allowed")
        auth = request.headers.get('Authorization', '')
        scheme, _, token = auth.partition(' ')
        if scheme.lower() != 'bearer' or not hmac.compare_digest(token.strip(), self.cfg.token):
            return json_error(401, "bad agent token")
        if request.path in (f'{API_PREFIX}/status', f'{API_PREFIX}/power/off'):
            request[IDENTITY_KEY] = None   # the portal itself, no user behind it
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
        occupied, reasons = self.occupied()
        managed = sum(1 for p in self.registry.projects.values() if p.managed)
        return web.json_response({
            'hostname': self.hostname, 'sre_version': params.sre_version,
            'projects': self.registry.count(), 'managed_projects': managed,
            'local_projects': self.registry.count() - managed,
            'terminals': sum(p.terminal_count() for p in self.registry.projects.values()),
            'displays': self.displays.running_count(),
            'exam_mode': self.exam_mode(), 'load1': load1, 'mem_available_mb': _mem_available_mb(),
            'occupied': occupied, 'occupied_by': reasons,
            'uptime': _uptime_seconds(), 'agent_uptime': round(time.monotonic() - self._started_at),
            'power_off_allowed': self.cfg.allow_power_off,
        })

    async def power_off(self, request):
        """The portal powers this idle host off: refused unless allowed, while a local session
        or any project exists; the command runs once the answer is sent."""
        if not self.cfg.allow_power_off:
            raise AccessError(403, "power off is not allowed on this host")
        occupied, reasons = self.occupied()
        if occupied:
            raise AccessError(409, f"the machine is occupied ({', '.join(reasons)})")
        if self.registry.count() > 0:
            raise AccessError(409, f"{self.registry.count()} project(s) running")
        log.warning("power off requested by %s: %s", request.remote, self.cfg.power_off_command)
        asyncio.get_running_loop().call_later(1.0, lambda: asyncio.ensure_future(self._run_power_off()))
        return web.json_response({'ok': True})

    async def _run_power_off(self):
        try:
            proc = await asyncio.create_subprocess_exec(*shlex.split(self.cfg.power_off_command))
            await proc.wait()
            if proc.returncode != 0:
                log.error("power off command failed (%s)", proc.returncode)
        except OSError as e:
            log.error("power off command failed: %s", e)

    async def labs_handler(self, request):
        if self.exam_mode():
            return web.json_response([])
        return web.json_response(await self.labs(request[IDENTITY_KEY].login))

    # -- projects --------------------------------------------------------------------------------

    async def projects_list(self, request):
        """The projects of the user; with ``?all=1`` (instructors only) every project of the host,
        with its owner's full name and student group (the answers metadata) and the summary of
        its last archived evaluation (the Watch page)."""
        identity = request[IDENTITY_KEY]
        everyone = request.query.get('all', '') in ('1', 'true')
        if everyone and not identity.is_instructor:
            raise AccessError(403, "instructors only")
        projects = self.registry.visible_to(identity, all_projects=everyone)
        if everyone:
            await self.results.refresh({p.rln for p in projects})
        rows = []
        for p in projects:
            row = dict(p.to_dict(), title=common.project_title(p.info, lang_priority(identity, p.info)))
            if everyone:
                summary = self.results.summary(p.rln)
                answers = self.answers.read(p)
                row['fullname'] = str(answers.get(params.fullname_keyword, '') or '')
                row['group'] = str(answers.get(params.group_keyword, '') or '')
                row['last_eval'] = summary.to_json() if summary is not None else None
            rows.append(row)
        return web.json_response(rows)

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
        # an instructor's own project in instructor mode: privileged start (the texts kept, every
        # state listed); the project is theirs and follows the student path afterwards
        instructor_mode = bool(body.get('instructor_mode', False))
        if instructor_mode and not identity.is_instructor:
            raise AccessError(403, "instructors only")
        args = ['start'] + (['--instructor-mode'] if instructor_mode else [])
        flavor = body.get('flavor_json')
        if flavor is not None:
            if not isinstance(flavor, dict):
                raise AccessError(400, "flavor_json must be an object")
            args += ['--flavor-json', json.dumps(flavor)]
        args.append(lab)
        # the virtual desktop of the project: its number and cookie go to sre start (the containers
        # keep them), kept when the lab turns out to have an x11_host machine
        reservation = None
        if self.displays.ready:
            try:
                reservation = self.displays.reserve()
            except DisplayError as e:
                raise AccessError(503, str(e))
        try:
            return await self._stream_creation(request, identity, args, body.get('idle_timeout'),
                                               reservation=reservation, privileged=instructor_mode)
        finally:
            if reservation is not None:
                self.displays.release(reservation)

    async def _stream_creation(self, request, identity: Identity, args: list, idle_timeout, *, reservation=None,
                               privileged: bool = False):
        """``sre start`` as an NDJSON stream (privileged: ``--instructor-mode``)."""
        try:
            idle = None if idle_timeout is None else max(0.0, float(idle_timeout))
        except (TypeError, ValueError):
            raise AccessError(400, "bad idle_timeout")
        resp = web.StreamResponse(status=200, headers={'Content-Type': NDJSON, 'Cache-Control': 'no-cache'})
        await resp.prepare(request)

        async def line(obj):
            await resp.write(json.dumps(obj).encode('utf-8') + b'\n')

        try:
            run = await self.runner.stream(identity.login, args, privileged=privileged, lang=identity.language,
                                           env=self.displays.env_for(reservation) if reservation else None)
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
        if reservation is not None and access.display_available(project.info, identity):
            self.displays.commit(project, reservation)
        self.registry.write_state(project, force=True)
        # the answers metadata (login, full name, group...) from the start: the Watch page names
        # the owner before the first answer; a failure must not cut the stream, the first PUT
        # writes the file anyway
        try:
            await self.answers.rewrite(project, identity)
        except OSError as e:
            log.warning("cannot write the answers metadata of %s: %s", project.rln, e)
        await line({'phase': 'result', 'status': 'created', 'running_lab_name': project.rln, 'host': self.hostname})
        return resp

    async def project_get(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        return web.json_response({
            'project': self._view(project, identity),
            'answers': AnswersStore.public(self.answers.read(project), project),
            'answers_readonly': project.owner != identity.login,
            'owner': project.owner,
            'terminals': project.terminal_list(identity),
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

    async def schema_pdf(self, request):
        """The Export Schema to PDF button: the drawing of the Schema tab rendered here by
        graphviz, like the GUI does in its own process (no ``sre`` call), as a download named
        ``<lab>_schema.pdf``; refused by the lab's ``export_schema_pdf`` flag."""
        project = self._project(request)
        access.check_schema_pdf(project.info)
        try:
            pdf = await asyncio.to_thread(schema_pdf, project.info, request[IDENTITY_KEY], request.query)
        except ValueError as e:
            raise AccessError(400, str(e))
        name = params.get_abbreviated_lab_name_from_running_lab_name(project.rln)
        return web.Response(body=pdf, content_type='application/pdf',
                            headers={'Content-Disposition': f'attachment; filename="{name}_{params.pdf_schema_file}"',
                                     'Cache-Control': 'no-cache'})

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
        access.check_is_owner(project.rln, request[IDENTITY_KEY])   # an instructor only reads them
        body = await self._read_json(request)
        patch = body.get('answers', body)
        if not isinstance(patch, dict):
            raise AccessError(400, "answers must be an object")
        data = await self.answers.put(project, patch, request[IDENTITY_KEY])
        return web.json_response({'answers': AnswersStore.public(data, project),
                                  'answers_updated_at': data.get(params.sysreseval_answers_updated_at, '')})

    async def eval_post(self, request):
        """The student's self-evaluation (``sre --user eval --auto-eval``, cooldown and counters
        of the lab), or, for an instructor on somebody else's project, a privileged ``sre eval``
        (exo-eval marks, no cooldown, nothing counted on the student's side)."""
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        privileged = access.is_privileged_caller(project.rln, identity)
        if not privileged:
            access.check_self_grade(project.info)
        access.check_not_exam(self.pub_dir)
        if project.lock.locked():
            raise AccessError(409, "the project is busy")
        async with project.lock:
            if privileged:
                result = await self.runner.run(identity.login, ['eval', project.rln], privileged=True,
                                               lang=identity.language)
            else:
                result = await self.runner.run(project.owner, ['eval', '--auto-eval', project.rln],
                                               lang=identity.language)
        self.results.invalidate()
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
                                  'delay_before_self_grade': 0 if privileged else data.get('delay_before_self_grade', 0)})

    async def state_post(self, request):
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        state = request.match_info.get('state', '')
        access.check_state(project.info, state, identity)
        access.check_not_exam(self.pub_dir)
        if project.lock.locked():
            raise AccessError(409, "the project is busy")
        privileged = access.is_privileged_caller(project.rln, identity)
        async with project.lock:
            await self.runner.run(identity.login if privileged else project.owner, ['state', project.rln, state],
                                  privileged=privileged, lang=identity.language)
        answers = await self.answers.consume_cheat(project)
        if answers is None:
            answers = self.answers.read(project)
        return web.json_response({'ok': True, 'answers': AnswersStore.public(answers, project)})

    async def evaluation_get(self, request):
        """Instructors: the last archived evaluation of the project (exo-eval scope), as rows of
        the evaluation table, with the errors of the run."""
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        if not identity.is_instructor:
            raise AccessError(403, "instructors only")
        found = await self.results.archive(project.rln)
        if found is None:
            raise AccessError(404, "no archived evaluation")
        summary, raw = found
        debug = project.debug
        translate = translator(identity.language, self.localedirs)
        rows = rows_to_json(build_evaluation_rows(
            exo_grade_list(raw, debug=debug), raw.get('grade_parts') or [], mark=summary.mark,
            maximum_mark=summary.maximum_mark, debug=debug, lang_priority=lang_priority(identity, project.info),
            translate=translate))
        body = summary.to_json()
        body.update({'rows': rows, 'header': header_labels(debug=debug, translate=translate),
                     'error_count': summary.errors, 'warning_count': summary.warnings,
                     'errors': error_entries(raw.get('errors'))})
        return web.json_response(body)

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
        """A terminal on a device: a new ``sre connect`` session, or (``?join=<id>``) one more
        browser on a live session of the project (``terminals.TerminalSession``: everybody types
        into the same pty and sees the same output).  A session of a non-owner instructor runs
        ``sre connect`` privileged (every listed device opens); ``?private=1`` (instructors) keeps
        it out of the student's list.  ``?readonly=1`` with ``join`` attaches a read-only client
        (a spectator of a presentation): its frames are ignored, it is told the size of the pty
        (``cols`` / ``rows`` in ``ready``, then ``{"t": "size"}`` frames), it has its own cap."""
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        device = request.match_info.get('device', '')
        q = request.query
        ws = web.WebSocketResponse(protocols=(TERMINAL_SUBPROTOCOL,), heartbeat=WS_HEARTBEAT, max_msg_size=1 << 20)
        session = None
        privileged = private = False
        readonly = q.get('readonly', '') in ('1', 'true')
        try:
            access.check_not_exam(self.pub_dir)
            if project.closing:
                raise AccessError(404, "the project is closing")
            join = q.get('join', '')
            if readonly and not join:
                raise AccessError(403, "a read-only terminal must join a session")
            if join:
                session = project.terminals.get(join)
                if session is None or session.closing or session.device != device:
                    raise AccessError(404, "this terminal is gone")
                if not session.visible_to(identity):
                    raise AccessError(403, "private terminal")
                if readonly:
                    if session.viewer_count() >= MAX_READONLY_CLIENTS_PER_SESSION:
                        raise AccessError(429, "too many viewers on this terminal")
                elif session.writer_count() >= MAX_CLIENTS_PER_SESSION:
                    raise AccessError(429, "too many viewers on this terminal")
            else:
                private = q.get('private', '') in ('1', 'true')
                if private and not identity.is_instructor:
                    raise AccessError(403, "private terminals are for instructors")
                privileged = access.is_privileged_caller(project.rln, identity)
                access.check_device(project.info, device, identity, connect_all=privileged)
                if (project.terminal_count() >= self.cfg.terminals_per_project
                        or project.terminals_on(device) >= self.cfg.terminals_per_device):
                    raise AccessError(429, "too many terminals")
        except AccessError as e:
            await ws.prepare(request)
            await ws.send_json({'t': 'error', 'message': e.message})
            await ws.close(code={403: WS_FORBIDDEN, 404: WS_NOT_FOUND, 429: WS_LIMIT}.get(e.status, WS_FORBIDDEN),
                           message=e.message.encode())
            return ws
        await ws.prepare(request)
        cols, rows = self._size(q)
        if session is None:
            user = identity.login if privileged else project.owner
            env = build_env(user, privileged=privileged, term='xterm-256color', lang=identity.language)
            env.update(self.runner.extra_env)
            session = TerminalSession(
                self._new_terminal_id(project), device,
                build_argv(self.cfg.sre_exe, ['connect', project.rln, device], privileged=privileged), env,
                created_by=identity.login, private=private, cols=cols, rows=rows,
                on_change=lambda: self._terminals_changed(project),
                on_closed=lambda s: self._terminal_closed(project, s), on_activity=project.touch)
            project.terminals[session.id] = session
            try:
                await session.start()
            except OSError as e:
                project.terminals.pop(session.id, None)
                await ws.send_json({'t': 'error', 'message': f"cannot start the terminal: {e}"})
                await ws.close(code=WS_NOT_FOUND)
                return ws
            log.info("terminal %s/%s opened for %s%s%s", project.rln, device, identity.login,
                     " (privileged)" if privileged else "", " (private)" if private else "")
            self._terminals_changed(project)
        else:
            log.info("terminal %s/%s joined by %s%s", project.rln, device, identity.login,
                     " (read-only)" if readonly else "")

        async def close_client(code: int, message: str):
            with contextlib.suppress(Exception):
                await ws.close(code=code, message=message.encode())

        client = session.attach(identity, send_bytes=ws.send_bytes, send_json=ws.send_json, close=close_client,
                                cols=cols, rows=rows, readonly=readonly)
        await ws.send_json({'t': 'ready', 'session': session.id, 'device': session.device,
                            'clients': session.writer_count(), 'viewers': session.viewer_count(),
                            'cols': session.size[0], 'rows': session.size[1], 'readonly': readonly,
                            'joined': bool(q.get('join', ''))})
        pump = asyncio.ensure_future(session.pump(client))
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
                if readonly:
                    continue           # a viewer: nothing it sends reaches the pty
                if msg.type == WSMsgType.BINARY:
                    session.type_in(msg.data)
                    project.touch()
                elif msg.type == WSMsgType.TEXT:
                    try:
                        obj = json.loads(msg.data)
                    except ValueError:
                        continue
                    if isinstance(obj, dict) and obj.get('t') == 'resize':
                        c, r = self._size({'cols': obj.get('cols'), 'rows': obj.get('rows')})
                        session.resize_client(client, c, r)
                    elif isinstance(obj, dict) and obj.get('t') == 'input' and isinstance(obj.get('data'), str):
                        session.type_in(obj['data'].encode('utf-8'))
                        project.touch()
        finally:
            pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pump
            session.detach(client)   # the last client takes the session with it
            log.info("terminal %s/%s left by %s", project.rln, device, identity.login)
        return ws

    @staticmethod
    def _new_terminal_id(project: Project) -> str:
        while True:
            session_id = secrets.token_urlsafe(6)
            if session_id not in project.terminals:
                return session_id

    def _terminals_changed(self, project: Project):
        """Push the list of live sessions to the subscribers of the project, once per loop turn
        however many changes happen in it."""
        if project._terminals_push_pending:
            return
        project._terminals_push_pending = True
        asyncio.get_running_loop().call_soon(lambda: asyncio.ensure_future(self._push_terminals(project)))

    async def _push_terminals(self, project: Project):
        project._terminals_push_pending = False
        await self.registry.broadcast(project, lambda identity, p=project: {
            't': EVENT_TERMINALS, 'terminals': p.terminal_list(identity)})

    def _terminal_closed(self, project: Project, session):
        if project.terminals.pop(session.id, None) is not None:
            self._terminals_changed(project)

    # -- the virtual desktop ---------------------------------------------------------------------

    async def display_get(self, request):
        project = self._project(request)
        return web.json_response(self.displays.status(project, access.display_available(project.info,
                                                                                         request[IDENTITY_KEY])))

    async def display_post(self, request):
        """The X server of the project, started (again) if needed."""
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        access.check_display(project.info, identity)
        access.check_not_exam(self.pub_dir)
        if project.closing or project.display is None:
            raise AccessError(404, "no display for this project")
        try:
            await self.displays.ensure(project)
        except DisplayError as e:
            raise AccessError(503, str(e))
        return web.json_response(self.displays.status(project, True))

    async def display_ws(self, request):
        """The RFB stream of the X server of the project, for noVNC: binary frames only, raw bytes
        both ways; a failure is a close code (4403 / 4404 like the terminals, 4500 when the X
        server is not there), never a text frame.  ``?readonly=1`` (a spectator of a
        presentation): the client messages go through ``RfbInputFilter`` (the handshake and the
        update requests pass, the input and the desktop changes are dropped, anything else
        closes the socket with 4403)."""
        project = self._project(request)
        identity = request[IDENTITY_KEY]
        readonly = request.query.get('readonly', '') in ('1', 'true')
        rfb_filter = RfbInputFilter() if readonly else None
        ws = web.WebSocketResponse(protocols=(DISPLAY_SUBPROTOCOL,), heartbeat=WS_HEARTBEAT, max_msg_size=1 << 20)
        try:
            access.check_display(project.info, identity)
            access.check_not_exam(self.pub_dir)
            if project.closing or project.display is None:
                raise AccessError(404, "no display for this project")
            session = await self.displays.ensure(project)
            reader, writer = await asyncio.open_unix_connection(str(session.socket_path))
        except AccessError as e:
            await ws.prepare(request)
            await ws.close(code={404: WS_NOT_FOUND}.get(e.status, WS_FORBIDDEN), message=e.message.encode())
            return ws
        except (DisplayError, OSError) as e:
            await ws.prepare(request)
            await ws.close(code=WS_DISPLAY_FAILED, message=str(e).encode())
            return ws
        await ws.prepare(request)
        project.display_clients.append(ws)
        project.touch()
        log.info("display %s opened for %s%s", project.rln, identity.login, " (read-only)" if readonly else "")

        async def sender():
            try:
                while True:
                    data = await reader.read(DISPLAY_CHUNK)
                    if not data:
                        break
                    await ws.send_bytes(data)
            except (OSError, ConnectionError):
                pass
            with contextlib.suppress(Exception):
                await ws.close(code=WS_DISPLAY_FAILED, message=b"the X server closed the connection")

        sender_task = asyncio.ensure_future(sender())
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    data = msg.data
                    if rfb_filter is not None:
                        try:
                            data = rfb_filter.feed(data)
                        except RfbProtocolError as e:
                            log.info("display %s: read-only viewer sent %s", project.rln, e)
                            with contextlib.suppress(Exception):
                                await ws.close(code=WS_FORBIDDEN, message=b"unexpected RFB message")
                            break
                    if data:
                        writer.write(data)
                        await writer.drain()
                    if rfb_filter is None:
                        project.touch()
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        except (OSError, ConnectionError):
            pass
        finally:
            sender_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sender_task
            with contextlib.suppress(ValueError):
                project.display_clients.remove(ws)
            writer.close()
            log.info("display %s closed", project.rln)
        return ws

    @staticmethod
    def _size(query) -> tuple[int, int]:
        def num(key, default, maximum):
            try:
                return max(2, min(maximum, int(query.get(key, default) or default)))
            except (TypeError, ValueError):
                return default
        return num('cols', 80, MAX_TERMINAL_COLS), num('rows', 24, MAX_TERMINAL_ROWS)
