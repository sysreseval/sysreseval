"""The handlers of the portal: the pages (Jinja2) and the ``/api/...`` endpoints relayed to the
agents (``relay.py``).  Every ``/api`` call needs the session cookie (in proxy mode, the identity
headers of the reverse proxy); the non-GET ones and the WebSockets need the
``X-Requested-With: sre-web`` header (CSRF)."""
import asyncio
import contextlib
import hmac
import json
import logging
import urllib.parse
from dataclasses import replace

import aiohttp_jinja2
from aiohttp import web, WSMsgType

from . import auth_anon, session as S
from .accesslog import AccessLog, ACCESS_KEY, ALL_EVENTS, LOGIN_EVENTS
from .accesshistory import (parse_filters, session_filters, session_of_row, session_of_visit, visit_matches, resolve_group,
                            UNLOGGED_FILTERS, HistoryError)
from .accessstats import statistics_window, statistics_query, compute_statistics, MAX_ROWS
from .archives import ArchiveStore, parse_archive_filters, SHOW_STUDENT, MAX_SUMMARY_ROWS
from .auth_ldap import LdapAuthenticator, LdapError
from .groups import (Memberships, GroupError, KINDS, KIND_CUSTOM, MAX_BATCH, MAX_DESCRIPTION, check_group_name,
                     group_dict, group_key, parse_group_key, sort_key as group_sort_key)
from .pool import Pool, PoolError
from .presentation import (Presence, Presentation, Presentations, Watcher, SPECTATOR_KEY, WS_PRESENTATION_ENDED,
                           MAX_VIEW_BYTES, MAX_EVALUATION_BYTES, MAX_PAGE_LENGTH, parse_audience, audience_size)
from .focus import Focus, Focuses, WS_FOCUS_ENDED
from .exams import (Exams, Exam, Member, PHASE_STARTING, START_PHASES, REASON_ADDRESS, lab_of_rln, normal_lab,
                    parse_exam, parse_labs, parse_selection, parse_extra_minutes)
from .examprojects import ExamProjects, exam_payload, instructor_identity
from .pool import LAB_KIND_LAB, LAB_SORT_NAME
from .ratelimit import RateLimiter
from .relay import Relay
from .roles import complete_owners
from ..agent.runner import RESULT_FLAVOR_FORM, RESULT_FLAVOR_ERROR, RESULT_CREATED
from ..config import WebConfig, AUTH_LDAP, AUTH_ANONYMOUS, AUTH_PROXY, host_config_from_dict, ConfigError
from ..identity import (Identity, IdentityError, ROLE_INSTRUCTOR, running_lab_name_owner, VIEW_INSTRUCTOR, IDENTITY_KEY,
                        is_valid_login)

#: Where the institution's logo of ``[site] logo`` is served.
SITE_LOGO_PATH = '/site/logo'
from ..i18n import translator, catalog

log = logging.getLogger('sreweb.portal')

TERMINAL_SUBPROTOCOL = 'sre-term.v1'
DISPLAY_SUBPROTOCOL = 'sre-display.v1'   # the RFB stream of the virtual X desktop (binary frames only)
LANGUAGE_NAMES = {'en': 'English', 'fr': 'Français'}
#: The security policy of every page; the page of a presentation (``/present/{id}``) is shown in
#: an iframe of the student's current page, so it alone allows a same-origin frame ancestor.
CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
CSP_FRAMED = CSP.replace("frame-ancestors 'none'", "frame-ancestors 'self'")
#: ``(method, canonical route)`` of the project calls a spectator of a presentation may make: they
#: are relayed with the presenter's identity (``Routes._target``), read-only by construction (the
#: terminal socket must join a session and gets ``readonly=1``, the display socket ``readonly=1``).
#: The last archived evaluation is not among them: the spectators show the table of the
#: presenter's page, which their presentation socket carries (``Presentations.set_evaluation``).
SPECTATOR_ROUTES = frozenset({
    ('GET', '/api/projects/{host}/{rln}'),
    ('GET', '/api/projects/{host}/{rln}/events'),
    ('GET', '/api/projects/{host}/{rln}/schema.svg'),
    ('GET', '/api/projects/{host}/{rln}/log'),
    ('GET', '/api/projects/{host}/{rln}/terminals/{device}'),
    ('GET', '/api/projects/{host}/{rln}/display'),
    ('GET', '/api/projects/{host}/{rln}/display/ws'),
    ('POST', '/api/projects/{host}/{rln}/touch'),
})


def json_error(status: int, message: str, **extra) -> web.Response:
    return web.json_response({'error': message, 'status': status, **extra}, status=status)


class ExamRefusal(PoolError):
    """A project call of a student refused by the rules of their exam (403; the pages redirect
    to the Projects page, where the exam bar says why)."""

    def __init__(self, reason: str):
        super().__init__(403, reason)


#: The reports reading thousands of rows (the statistics of the History page, the lab summary of
#: the Archives page): HEAVY_QUERIES at a time, a request waiting HEAVY_WAIT seconds at most for
#: a slot, else a 503 asking to retry after HEAVY_RETRY_AFTER (the clicks of the administrators
#: and instructors cannot pile such reads up in the thread executor every query shares).
HEAVY_QUERIES = 2
HEAVY_WAIT = 10.0
HEAVY_RETRY_AFTER = 5

#: Why a sign-in fails, by code (the ``reason`` of the ``login_failed`` lines of the connection
#: log too): the status and message of the JSON API.  The form redirects to ``/login?error=<code>``
#: and ``login.html`` shows its own text for the code, never a text taken from the URL (a link
#: ``?error=Your+account+is+locked…`` would otherwise show inside the real sign-in box).
LOGIN_ERRORS = {
    'password': (401, "wrong login or password"),
    'rate_limited': (429, "too many login attempts, try again in a minute"),
    'directory': (502, "the directory does not answer"),
    'proxy_mode': (403, "the authentication is done by the reverse proxy"),
}


class LoginRefused(PoolError):
    """A sign-in that failed for one of the ``LOGIN_ERRORS`` codes."""

    def __init__(self, code: str):
        status, message = LOGIN_ERRORS[code]
        super().__init__(status, message)
        self.code = code


class Routes:
    def __init__(self, cfg: WebConfig, pool: Pool, relay: Relay, *, localedirs, manager=None, access: AccessLog,
                 presentations: Presentations | None = None, roles=None, focuses: Focuses | None = None,
                 archives: ArchiveStore | None = None, memberships: Memberships | None = None,
                 exams: Exams | None = None, exam_projects: ExamProjects | None = None):
        self.cfg = cfg
        self.pool = pool
        self.roles = roles       # the directory lookups (roles.RoleCache) completing the Watch rows' groups
        self.manager = manager
        self.relay = relay
        self.access = access
        self.archives = archives     # the evaluation archives in the database (None without one)
        # the user groups (groups.Memberships: the directory and the custom groups, either may be missing)
        self.memberships = memberships if memberships is not None else Memberships()
        self.presentations = presentations if presentations is not None else Presentations(Presence())
        self.presence = self.presentations.presence
        self.focuses = focuses if focuses is not None else Focuses(self.presence)
        # the exams (exams.Exams: in memory, the database behind when there is one) and their
        # projects on the agents (examprojects.ExamProjects, None = the agents are not told)
        self.exams = exams if exams is not None else Exams(self.presence, memberships=self.memberships, cfg=cfg.exams)
        self.exam_projects = exam_projects
        self.localedirs = localedirs
        self.limiter = RateLimiter()
        self._heavy = asyncio.Semaphore(HEAVY_QUERIES)     # the slots of the heavy reports (_heavy_acquire)
        self.heavy_wait = HEAVY_WAIT
        self.ldap = LdapAuthenticator(cfg.auth.ldap) if cfg.auth.mode == AUTH_LDAP else None

    def register(self, app: web.Application):
        r = app.router
        r.add_get('/', self.index)
        r.add_get('/login', self.login_page)
        r.add_post('/login', self.login_form)
        r.add_post('/logout', self.logout)
        r.add_get('/projects', self.projects_page)
        r.add_get('/open', self.open_page)
        r.add_get('/watch', self.watch_page)
        r.add_get('/pool', self.pool_page)
        r.add_get('/history', self.history_page)
        r.add_get('/archives', self.archives_page)
        r.add_get('/groups', self.groups_page)
        r.add_get('/exams', self.exams_page)
        r.add_get('/projects/{host}/{rln}', self.project_page)
        r.add_get('/i18n/{lang}.json', self.i18n_catalog)
        r.add_get(SITE_LOGO_PATH, self.site_logo)
        r.add_get('/api/me', self.api_me)
        r.add_post('/api/login', self.api_login)
        r.add_post('/api/logout', self.logout)
        r.add_post('/api/language', self.api_language)
        r.add_get('/api/labs', self.api_labs)
        r.add_get('/api/pool', self.api_pool)
        r.add_get('/api/pool/status', self.api_pool_status)
        r.add_post('/api/pool/hosts', self.api_pool_add)
        r.add_delete('/api/pool/hosts/{name}', self.api_pool_remove)
        r.add_post('/api/pool/hosts/{name}/{action}', self.api_pool_action)
        r.add_get('/api/projects', self.api_projects)
        r.add_get('/api/watch', self.api_watch)
        r.add_get('/api/watch/evaluations', self.api_watch_evaluations)
        r.add_get('/api/history', self.api_history)
        r.add_get('/api/history/sessions', self.api_history_sessions)
        r.add_get('/api/history/statistics', self.api_history_statistics)
        # the archives of the evaluations (the fixed paths before the id one)
        r.add_get('/api/archives', self.api_archives)
        r.add_get('/api/archives/summary', self.api_archives_summary)
        r.add_get('/api/archives/options', self.api_archives_options)
        r.add_get('/api/archives/{id}', self.api_archive)
        # the user groups (the fixed paths before the parametrised ones)
        r.add_get('/api/groups', self.api_groups)
        r.add_post('/api/groups', self.api_group_create)
        r.add_get('/api/groups/people', self.api_groups_people)
        r.add_get('/api/groups/{kind}/{name}', self.api_group)
        r.add_put('/api/groups/custom/{name}', self.api_group_update)
        r.add_delete('/api/groups/custom/{name}', self.api_group_delete)
        r.add_post('/api/groups/custom/{name}/members', self.api_group_members_add)
        r.add_delete('/api/groups/custom/{name}/members', self.api_group_members_remove)
        r.add_delete('/api/groups/custom/{name}/members/{login}', self.api_group_member_remove)
        # the exams: the student's own (the exam binding them), then the instructors' (the fixed
        # paths before the id one)
        r.add_get('/api/exam', self.api_exam)
        r.add_post('/api/exam/{id}/dismiss', self.api_exam_dismiss)
        r.add_get('/api/exams', self.api_exams)
        r.add_post('/api/exams', self.api_exam_create)
        r.add_get('/api/exams/{id}', self.api_exam_get)
        r.add_put('/api/exams/{id}', self.api_exam_update)
        r.add_delete('/api/exams/{id}', self.api_exam_delete)
        r.add_post('/api/exams/{id}/end', self.api_exam_end)
        r.add_post('/api/exams/{id}/adjust', self.api_exam_adjust)
        r.add_post('/api/exams/{id}/labs', self.api_exam_labs)
        r.add_post('/api/exams/{id}/close-projects', self.api_exam_close_projects)
        r.add_post('/api/projects', self.api_projects_create)
        r.add_get('/api/projects/{host}/{rln}', self.api_project_get)
        r.add_delete('/api/projects/{host}/{rln}', self.api_project_close)
        r.add_get('/api/projects/{host}/{rln}/events', self.api_events)
        r.add_get('/api/projects/{host}/{rln}/schema.svg', self.api_schema)
        r.add_get('/api/projects/{host}/{rln}/schema.pdf', self.api_schema_pdf)
        r.add_put('/api/projects/{host}/{rln}/answers', self.api_answers)
        r.add_post('/api/projects/{host}/{rln}/eval', self.api_eval)
        r.add_get('/api/projects/{host}/{rln}/evaluation', self.api_evaluation)
        r.add_post('/api/projects/{host}/{rln}/states/{state}', self.api_state)
        r.add_get('/api/projects/{host}/{rln}/terminals/{device}', self.api_terminal)
        r.add_get('/api/projects/{host}/{rln}/display', self.api_display)
        r.add_post('/api/projects/{host}/{rln}/display', self.api_display_start)
        r.add_get('/api/projects/{host}/{rln}/display/ws', self.api_display_ws)
        r.add_get('/api/projects/{host}/{rln}/log', self.api_log)
        r.add_post('/api/projects/{host}/{rln}/touch', self.api_touch)
        # presentations: an instructor's project shown read-only on the students' browsers
        r.add_get('/present/{id}', self.present_page)
        r.add_get('/api/presence/ws', self.api_presence_ws)
        r.add_get('/api/presence', self.api_presence)
        r.add_get('/api/presentations', self.api_presentations)
        r.add_post('/api/presentations', self.api_presentation_create)
        r.add_get('/api/presentations/{id}', self.api_presentation_get)
        r.add_put('/api/presentations/{id}/audience', self.api_presentation_audience)
        r.add_put('/api/presentations/{id}/view', self.api_presentation_view)
        r.add_put('/api/presentations/{id}/evaluation', self.api_presentation_evaluation)
        r.add_delete('/api/presentations/{id}', self.api_presentation_delete)
        r.add_get('/api/presentations/{id}/ws', self.api_presentation_ws)
        # focus: an instructor helping a student keeps the student's browser on the project
        r.add_get('/api/focus', self.api_focus_list)
        r.add_post('/api/focus', self.api_focus_create)
        r.add_get('/api/focus/{id}', self.api_focus_get)
        r.add_put('/api/focus/{id}/view', self.api_focus_view)
        r.add_delete('/api/focus/{id}', self.api_focus_delete)
        r.add_get('/api/focus/{id}/ws', self.api_focus_ws)

    # -- helpers --------------------------------------------------------------------------------

    @property
    def proxy_mode(self) -> bool:
        """The reverse proxy authenticates and passes the identity in headers (no login page)."""
        return self.cfg.auth.mode == AUTH_PROXY

    def _secure(self, request) -> bool:
        return self.cfg.public_url.lower().startswith('https://') or request.scheme == 'https'

    def _language(self, request) -> str:
        identity = request.get(IDENTITY_KEY)
        if identity is not None:
            return identity.language
        return S.choose_language((request.query.get('lang'), request.cookies.get(S.LANG_COOKIE)), self.cfg.languages)

    def _translate(self, request):
        return translator(self._language(request), self.localedirs)

    def _page_context(self, request, **extra) -> dict:
        identity = request.get(IDENTITY_KEY)
        language = self._language(request)
        return {
            '_': self._translate(request),
            'identity': identity.to_dict() if identity else None,
            'auth_mode': self.cfg.auth.mode,
            'languages': [(code, LANGUAGE_NAMES.get(code, code)) for code in self.cfg.languages],
            'language': language,
            'instructor': bool(identity and identity.role == ROLE_INSTRUCTOR),
            'administrator': bool(identity and identity.administrator),   # the History link
            'groups': self.cfg.groups_configured,     # the Watch page shows the student groups (its Group column)
            'group_sources': self.cfg.group_sources,  # any user groups: the group select, the Present audience
            'logout_url': self.cfg.auth.proxy.logout_url if self.proxy_mode else '',
            'site': self._site(language),
            **extra,
        }

    def _site(self, language: str) -> dict:
        """``[site]`` for the header of the pages: the institution's name in *language*, its
        link, and the URL of its logo ('' without one)."""
        site = self.cfg.site
        return {'name': site.name_for(language, self.cfg.languages), 'url': site.url,
                'logo_url': SITE_LOGO_PATH if site.logo else ''}

    def _require_identity(self, request) -> Identity:
        identity = request.get(IDENTITY_KEY)
        if identity is None:
            raise web.HTTPUnauthorized(text=json.dumps({'error': 'not logged in', 'status': 401}),
                                       content_type='application/json')
        return identity

    def _require_instructor(self, request) -> Identity:
        identity = self._require_identity(request)
        if identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "instructors only")
        return identity

    def _require_administrator(self, request) -> Identity:
        identity = self._require_identity(request)
        if not identity.administrator:
            raise PoolError(403, "administrators only")
        return identity

    def _target(self, request) -> tuple:
        """The host and running lab name of a project URL, after the ownership check.  A
        spectator of a presentation of that project gets the presenter's identity (their own
        language) on the read-only routes of ``SPECTATOR_ROUTES``, the instructor view following
        the presenter's; ``request[SPECTATOR_KEY]`` then holds the presentation."""
        identity = self._require_identity(request)
        host = self.pool.host(request.match_info['host'])
        rln = request.match_info['rln']
        owner = running_lab_name_owner(rln)
        if owner is None:
            raise PoolError(404, "unknown project")
        if owner != identity.login and identity.role != ROLE_INSTRUCTOR:
            presentation = self.presentations.spectator_of(identity, host.name, rln)
            canonical = getattr(request.match_info.route.resource, 'canonical', '') or ''
            method = 'GET' if request.method == 'HEAD' else request.method
            if presentation is None or (method, canonical) not in SPECTATOR_ROUTES:
                raise PoolError(403, "not your project")
            request[SPECTATOR_KEY] = presentation
            logged = request.get(ACCESS_KEY)
            if logged is not None:
                logged['spectator'] = True
            presenter = replace(presentation.presenter, language=identity.language)
            if presentation.view.get('instructorView') is True:
                presenter = presenter.with_view(VIEW_INSTRUCTOR)
            return host, rln, presenter
        if identity.role != ROLE_INSTRUCTOR:
            self._exam_check(request, identity, rln=rln)     # a student in an exam: its projects only
        view = request.query.get('view', '')
        if view == VIEW_INSTRUCTOR and identity.role == ROLE_INSTRUCTOR:
            identity = identity.with_view(VIEW_INSTRUCTOR)
        return host, rln, identity

    # -- the exam of a student (the rules of exams.Exams on the project routes) -------------------

    def _exam_binding(self, identity: Identity) -> tuple | None:
        """``(exam, member, phase)`` of the exam binding a student now; an instructor is never
        bound."""
        if identity.is_instructor:
            return None
        return self.exams.for_login(identity.login, identity.group)

    def _exam_check(self, request, identity: Identity, *, rln: str | None = None, lab: str | None = None):
        """``ExamRefusal`` (403) when the exam rules forbid a student's call: a browser outside
        the networks of their exam, a project that is not of the exam (*rln*) or a start of a
        lab that is not of the exam or too early (*lab*)."""
        binding = self._exam_binding(identity)
        if binding is not None:
            address = self.access.address(request)
            if not self.exams.address_allowed(binding[0], address):
                raise ExamRefusal(REASON_ADDRESS.format(address=address))
        if rln is not None:
            allowed, reason = self.exams.project_access(identity.login, identity.group, rln)
        elif lab is not None:
            allowed, reason = self.exams.start_access(identity.login, identity.group, lab)
        else:
            return
        if not allowed:
            raise ExamRefusal(reason)

    async def _sync_exam_member(self, exam: Exam, member: Member):
        """The agents of a student's exam projects told their exam object (best effort: the
        reconcile pass of ``ExamProjects`` tries again)."""
        if self.exam_projects is None:
            return
        try:
            await self.exam_projects.sync_member(exam, member)
        except Exception:
            log.exception("exam %d: syncing the projects of %s failed", exam.id, member.login)

    async def _lab_titles(self, exam: Exam) -> dict:
        """The titles of the labs, the exam-only ones included (the list of the instructors,
        fetched in the name of the exam's creator; cached by the pool)."""
        try:
            await self.pool.labs(instructor_identity(exam), all_labs=True)
        except Exception:
            log.exception("exam %d: the lab list could not be fetched", exam.id)
        return self.pool.lab_titles()

    def _check_language(self, language: str) -> str:
        return language if language in self.cfg.languages else self.cfg.languages[0]

    # -- pages ----------------------------------------------------------------------------------

    async def index(self, request):
        raise web.HTTPFound('/projects' if request.get(IDENTITY_KEY) else '/login')

    async def login_page(self, request):
        if request.get(IDENTITY_KEY):
            raise web.HTTPFound('/projects')
        code = request.query.get('error', '')       # a LOGIN_ERRORS code: the page has its own text for it
        return aiohttp_jinja2.render_template('login.html', request,
                                              self._page_context(request, error=code if code in LOGIN_ERRORS else ''))

    async def _authenticate(self, request, data: dict) -> Identity:
        """The identity of a login request; the outcome goes to the connection log (the
        request carries no identity, so the log's middleware cannot see it)."""
        login = str(data.get('login', '')).strip()
        if self.proxy_mode:
            self.access.login_failed(request, login, 'proxy_mode')
            raise LoginRefused('proxy_mode')
        language = self._check_language(str(data.get('language', '') or self._language(request)))
        if self.cfg.auth.mode == AUTH_ANONYMOUS:
            identity = auth_anon.new_guest(str(data.get('display_name', '')), language)
            self.access.login(request, identity, self.cfg.auth.mode)
            return identity
        # per client address: the one the proxy forwards, else every user shares the proxy's budget
        if not self.limiter.allow_per_minute('login', self.access.address(request), self.cfg.limits.login_per_minute):
            self.access.login_failed(request, login, 'rate_limited')
            raise LoginRefused('rate_limited')
        password = str(data.get('password', ''))
        try:
            identity = await self.ldap.authenticate(login, password, language)
        except LdapError as e:
            log.error("LDAP error: %s", e)
            self.access.login_failed(request, login, 'directory')
            raise LoginRefused('directory')
        if identity is None:
            self.access.login_failed(request, login, 'password')
            raise LoginRefused('password')
        self.access.login(request, identity, self.cfg.auth.mode)
        return identity

    async def login_form(self, request):
        data = await request.post()
        try:
            identity = await self._authenticate(request, dict(data))
        except LoginRefused as e:
            raise web.HTTPFound('/login?' + urllib.parse.urlencode({'error': e.code}))
        except PoolError:
            raise web.HTTPFound('/login')
        response = web.HTTPFound('/projects')
        S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request))
        raise response

    async def logout(self, request):
        """Clears the session cookie (a stale cookie of a previous mode too); in proxy mode the
        browser is sent to ``logout_url`` (the logout location or handler of the proxy) when
        there is one."""
        target = self.cfg.auth.proxy.logout_url if self.proxy_mode else ''
        if request.path.startswith('/api/'):
            response = web.json_response({'ok': True, 'logout_url': target})
        else:
            response = web.HTTPFound(target or '/login')
        S.clear_cookie(response)
        if isinstance(response, web.HTTPException):
            raise response
        return response

    async def projects_page(self, request):
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        return aiohttp_jinja2.render_template('projects.html', request, self._page_context(request))

    async def open_page(self, request):
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if self._exam_binding(request[IDENTITY_KEY]) is not None:
            raise web.HTTPFound('/projects')      # a student in an exam: the exam projects start by themselves
        return aiohttp_jinja2.render_template('open.html', request, self._page_context(request))

    async def watch_page(self, request):
        """Instructors: every running project of the pool with its last evaluation."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        return aiohttp_jinja2.render_template('watch.html', request, self._page_context(request))

    async def pool_page(self, request):
        """Instructors: the hosts of the pool with their state, and the actions of sre-web-tool
        (but add / remove)."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        return aiohttp_jinja2.render_template('pool.html', request, self._page_context(request))

    async def history_page(self, request):
        """Administrators: the connection log, read from its database (``[access_log.database]``;
        the page says so when none is configured), in three views: the sessions, the events, the
        statistics of a period.  The event select lists every event but, in proxy mode, those of
        the login page (never logged there)."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if not request[IDENTITY_KEY].administrator:
            raise web.HTTPForbidden(text="administrators only")
        events = [e for e in ALL_EVENTS if not (self.proxy_mode and e in LOGIN_EVENTS)]
        return aiohttp_jinja2.render_template('history.html', request, self._page_context(
            request, history_database=self.access.history is not None, events=events))

    async def archives_page(self, request):
        """Instructors: the archives of the evaluations of the pool, read from the database
        (``[archives]`` + ``[access_log.database]``; the page says so when none is configured):
        the evaluations found by the filters, the detail of one, the lab summary."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        return aiohttp_jinja2.render_template('archives.html', request, self._page_context(
            request, archives_database=self.archives is not None))

    async def groups_page(self, request):
        """Instructors: the user groups (the departments and the groups of the directory, the
        custom groups of the database), the members of each, the editing of the custom ones; the
        page says what is not configured."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        return aiohttp_jinja2.render_template('groups.html', request, self._page_context(
            request, groups_directory=self.memberships.directory is not None,
            groups_database=self.memberships.store is not None))

    async def exams_page(self, request):
        """Instructors: the exams (scheduled, running, past), the form of a new one, the detail
        of one with its students and the actions during the exam; the page says what is not
        configured (the database holding the exams, a mode without stable logins)."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        exams = self.cfg.exams
        return aiohttp_jinja2.render_template('exams.html', request, self._page_context(
            request, exams_database=self.exams.store is not None,
            exams_available=self.cfg.auth.mode != AUTH_ANONYMOUS,
            exam_defaults={'lead': exams.lead / 60, 'pre_start': exams.pre_start / 60,
                           'eval_interval': exams.eval_interval}))

    async def project_page(self, request):
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        try:
            host, rln, identity = self._target(request)
        except ExamRefusal:
            raise web.HTTPFound('/projects')      # the exam bar of the Projects page says why
        return aiohttp_jinja2.render_template('project.html', request, self._page_context(
            request, host=host.name, rln=rln, api_base=f"/api/projects/{host.name}/{urllib.parse.quote(rln)}"))

    async def i18n_catalog(self, request):
        lang = request.match_info['lang']
        if lang not in self.cfg.languages:
            raise web.HTTPNotFound()
        return web.json_response(catalog(lang, self.localedirs), headers={'Cache-Control': 'max-age=3600'})

    async def site_logo(self, request):
        """The institution's logo (``[site] logo``), next to the SRE logo on every page, the
        login page included: no session needed."""
        if not self.cfg.site.logo:
            raise web.HTTPNotFound()
        return web.FileResponse(self.cfg.site.logo, headers={'Cache-Control': 'max-age=3600'})

    # -- session API ----------------------------------------------------------------------------

    async def api_me(self, request):
        identity = request.get(IDENTITY_KEY)
        return web.json_response({'identity': identity.to_dict() if identity else None, 'auth_mode': self.cfg.auth.mode,
                                  'languages': self.cfg.languages})

    async def api_login(self, request):
        try:
            data = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        identity = await self._authenticate(request, data if isinstance(data, dict) else {})
        response = web.json_response({'identity': identity.to_dict()})
        S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request))
        return response

    async def api_language(self, request):
        identity = self._require_identity(request)
        try:
            data = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        language = self._check_language(str((data or {}).get('language', '')))
        identity = replace(identity, language=language)
        response = web.json_response({'identity': identity.to_dict()})
        S.set_language_cookie(response, language, secure=self._secure(request))
        if not self.proxy_mode:       # the session cookie carries the language; proxy mode has none
            S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request),
                         issued_at=request.get(S.SESSION_IAT_KEY))     # the session keeps its date: it never slides
        return response

    # -- labs, pool, projects -------------------------------------------------------------------

    async def api_labs(self, request):
        """The lab tree; ``?all=1`` (instructors) the exam-only labs too; a student in an exam
        gets its labs alone (nothing from a browser outside its networks, nothing once over)."""
        identity = self._require_identity(request)
        if request.query.get('all', '') in ('1', 'true'):
            self._require_instructor(request)
            return web.json_response(await self.pool.labs(identity, all_labs=True))
        binding = self._exam_binding(identity)
        if binding is not None:
            exam, member, phase = binding
            if phase not in START_PHASES or not self.exams.address_allowed(exam, self.access.address(request)):
                return web.json_response([])
            titles = await self._lab_titles(exam)
            return web.json_response([{'name': l.lab, 'title': titles.get(l.lab), 'kind': LAB_KIND_LAB,
                                       'sort': LAB_SORT_NAME} for l in exam.labs_of(identity.login)])
        return web.json_response(await self.pool.labs(identity))

    # -- the pool: sre-web-tool with the admin token; the listing and the actions (not add /
    # remove) for the instructors too (the Pool page) ---------------------------------------

    def _is_admin(self, request) -> bool:
        """The administration token (``[admin] token`` of web.toml), from the loopback unless
        ``listen_any``; every admin call is logged with its source."""
        token = self.cfg.admin.token
        scheme, _, given = request.headers.get('Authorization', '').partition(' ')
        if not token or scheme.lower() != 'bearer' \
                or not hmac.compare_digest(given.strip().encode('utf-8'), token.encode('utf-8')):
            return False
        if not self.cfg.admin.listen_any and request.remote not in ('127.0.0.1', '::1'):
            log.warning("admin call from %s refused (admin.listen_any is false)", request.remote)
            return False
        log.info("admin %s %s from %s", request.method, request.path, request.remote)
        return True

    def _require_pool_access(self, request) -> Identity | None:
        """The admin token (sre-web-tool) or an instructor's session (the Pool page): ``None``
        for the token, the identity otherwise."""
        if self._is_admin(request):
            return None
        if request.headers.get('Authorization'):
            raise PoolError(401, "bad administration token")
        identity = self._require_identity(request)
        if identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "instructors only")
        return identity

    def _require_admin(self, request):
        if not self._is_admin(request):
            raise PoolError(401, "bad administration token" if request.headers.get('Authorization')
                            else "the administration token is required")

    async def api_pool(self, request):
        self._require_pool_access(request)
        return web.json_response(self.pool.summary())

    async def api_pool_status(self, request):
        self._require_pool_access(request)
        return web.json_response(self.manager.status() if self.manager else {})

    async def api_pool_add(self, request):
        self._require_admin(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        try:
            host = host_config_from_dict(body if isinstance(body, dict) else {}, "host")
        except ConfigError as e:
            return json_error(400, str(e))
        self.pool.add_host(host)
        return web.json_response(self._host_row(host.name), status=201)

    async def api_pool_remove(self, request):
        self._require_admin(request)
        name = request.match_info['name']
        self.pool.remove_host(name, force=request.query.get('force', '') in ('1', 'true'))
        return web.json_response({'ok': True, 'removed': name})

    async def api_pool_action(self, request):
        """``enable`` / ``disable`` / ``wake`` / ``poweroff`` / ``drain`` / ``restart`` a host:
        the commands of sre-web-tool and the buttons of the Pool page (which has no Restart
        button: the tool alone offers it); the answer is the updated row."""
        identity = self._require_pool_access(request)
        name, action = request.match_info['name'], request.match_info['action']
        if action == 'enable':
            self.pool.set_enabled(name, True)
        elif action == 'disable':
            self.pool.set_enabled(name, False)
        elif action == 'wake':
            await self.manager.wake(name, "requested")
        elif action == 'poweroff':
            await self.manager.power_off(name, "requested")
        elif action == 'restart':
            await self.manager.restart(name, "requested")
        elif action == 'drain':
            self.pool.host(name)
            self.pool.runtime[name].drain = True
            log.info("host %s draining: no new project, power off when empty", name)
        else:
            return json_error(404, f"unknown action {action}")
        log.info("pool: %s %s by %s", action, name, identity.login if identity else "the admin token")
        return web.json_response(self._host_row(name))

    def _host_row(self, name: str) -> dict:
        return next((row for row in self.pool.summary() if row['name'] == name), {'name': name})

    async def api_projects(self, request):
        """The caller's running projects on the pool.  A student in an exam sees the exam
        projects alone (nothing from a browser outside its networks); their rows are how the
        portal learns that their exam projects are created (``Exams.observe``: their clock
        starts); the exam projects of an exam over for them stay hidden until closed."""
        identity = self._require_identity(request)
        rows = await self.pool.projects_of(identity)
        if identity.is_instructor:
            return web.json_response(rows)
        binding = self._exam_binding(identity)
        if binding is not None:
            exam, member, phase = binding
            address = self.access.address(request)
            if not self.exams.address_allowed(exam, address):
                await self.exams.note_seen(exam, identity.login, address)
                return web.json_response([])
            if await self.exams.observe(exam, identity.login, rows, address=address):
                await self._sync_exam_member(exam, exam.members[identity.login])
        return web.json_response(self.exams.visible_rows(identity.login, identity.group, rows))

    async def api_watch(self, request):
        """Instructors: every project of every reachable host, with its owner and the summary of
        its last archived evaluation (the agents read their archives); from the directory when
        it is readable, the group of the owners the agents know none for and the full name of
        the owners of the Qt GUI projects (``roles.complete_owners``)."""
        identity = self._require_instructor(request)
        rows = await self.pool.projects_of(identity, all_projects=True)
        if self.roles is not None:
            await complete_owners(rows, self.roles)
        await self.memberships.refresh()
        return web.json_response(self.memberships.annotate(rows))

    async def api_watch_evaluations(self, request):
        """Instructors: the lab summary of the Watch page, every running project of the lab
        ``?lab=`` on every reachable host with the elements of its last archived evaluation (the
        agents read their archives), the groups and the names completed as for ``/api/watch``."""
        identity = self._require_instructor(request)
        lab = request.query.get('lab', '')
        if not lab:
            return json_error(400, "a lab is expected")
        rows = await self.pool.evaluations_of(identity, lab)
        if self.roles is not None:
            await complete_owners(rows, self.roles)
        await self.memberships.refresh()
        return web.json_response(self.memberships.annotate(rows))

    async def _resolve_group(self, filters: dict) -> dict:
        """The ``group`` filter of a History query turned into the ``logins`` of the members of
        that group, of any kind (``accesshistory.resolve_group`` on the fresh memberships);
        ``ValueError`` (a 400) without any source of user groups: the select of the page is
        hidden then."""
        if filters.get('group'):
            if not self.memberships.available:
                raise ValueError("group: no source of user groups is configured")
            await self.memberships.refresh()
            resolve_group(filters, self.memberships)
        return filters

    @staticmethod
    def _group_fields(filters: dict) -> dict:
        """For the answer of a History query filtered by group: the key asked and the number of
        members found (0: the page says the table is empty for that reason)."""
        if not filters.get('group'):
            return {}
        return {'group': filters['group'], 'group_members': len(filters.get('logins') or ())}

    @staticmethod
    def _log_history_filters(logged, filters: dict, *skipped: str):
        """The filters asked on the ``history`` line (``<key>_filter``), but ``UNLOGGED_FILTERS``
        and *skipped*."""
        if logged is not None:
            logged.update({f'{key}_filter': value for key, value in filters.items()
                           if key not in UNLOGGED_FILTERS and key not in skipped})

    async def api_history(self, request):
        """Administrators: a page of the connection log from its database, newest first, with
        the filters of ``accesshistory.parse_filters`` (the group resolved into its members) and
        a cursor for the older pages; the call is a ``history`` line of the log carrying the
        filters asked (``<key>_filter``)."""
        self._require_administrator(request)
        if self.access.history is None:
            return json_error(409, "the connection log has no database ([access_log.database] of web.toml)")
        try:
            filters = await self._resolve_group(parse_filters(request.query))
        except ValueError as e:
            return json_error(400, str(e))
        self._log_history_filters(request.get(ACCESS_KEY), filters)
        try:
            page = await self.access.history.query(filters)
        except HistoryError as e:
            log.warning("access database: a history query failed: %s", e)
            return json_error(503, "the database of the connection log does not answer")
        return web.json_response({**page, 'limit': filters['limit'], **self._group_fields(filters),
                                  'database': self.access.db.status() if self.access.db is not None else None})

    async def api_history_sessions(self, request):
        """Administrators: the Sessions view of the History page.  ``open``: the sessions still
        open, from the portal's memory (the first page only, newest first); ``rows``: the closed
        ones from the database, one per ``session_close`` line, newest first, with the login /
        address prefixes, the group (its members, open sessions included), the time window (on
        the closing time) and the cursor of ``accesshistory.session_filters``.  Without a
        database the open sessions alone (no 409: who is connected now needs none).  A
        ``history`` line with ``view=sessions`` (whatever the answer) and the filters."""
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged['view'] = 'sessions'
        self._require_administrator(request)
        try:
            filters = await self._resolve_group(session_filters(parse_filters(request.query)))
        except ValueError as e:
            return json_error(400, str(e))
        self._log_history_filters(logged, filters, 'event')
        open_sessions = []
        if filters.get('before') is None:
            open_sessions = sorted((session_of_visit(v) for v in self.access.visits.all() if visit_matches(v, filters)),
                                   key=lambda s: s['start'], reverse=True)
        page = {'rows': [], 'more': False}
        if self.access.history is not None:
            try:
                page = await self.access.history.query(filters)
            except HistoryError as e:
                log.warning("access database: a history query failed: %s", e)
                return json_error(503, "the database of the connection log does not answer")
            page['rows'] = [session_of_row(row) for row in page['rows']]
        return web.json_response({**page, 'open': open_sessions, 'limit': filters['limit'], **self._group_fields(filters),
                                  'database': self.access.db.status() if self.access.db is not None else None})

    # -- the archives of the evaluations ---------------------------------------------------------

    def _archives_reader(self):
        """The reader of the archives table, or 409 when the evaluations are not stored."""
        if self.archives is None:
            raise PoolError(409, "the evaluations are not stored in a database ([access_log.database] of web.toml)")
        return self.archives.reader

    @staticmethod
    def _log_archive_filters(request, filters: dict, **extra):
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update({f'{key}_filter': value for key, value in filters.items() if key != 'limit'})
            logged.update(extra)

    async def api_archives(self, request):
        """Instructors: a page of the archives of the evaluations, newest first, with the
        filters of ``archives.parse_archive_filters`` (the newest evaluation of each project by
        default) and a cursor for the older pages; an ``archives`` line of the log with the
        filters asked (``<key>_filter``)."""
        self._require_instructor(request)
        reader = self._archives_reader()
        try:
            filters = parse_archive_filters(request.query)
        except ValueError as e:
            return json_error(400, str(e))
        self._log_archive_filters(request, filters)
        try:
            page = await reader.query(filters)
        except HistoryError as e:
            log.warning("archives database: a query failed: %s", e)
            return json_error(503, "the database of the archives does not answer")
        return web.json_response({**page, 'limit': filters['limit'], 'database': self.archives.status()})

    async def api_archives_summary(self, request):
        """Instructors: the lab summary of the Archives page: the rows of the filters (the
        newest evaluation of each student by default) with their elements, for one lab
        (``lab`` required), at most ``MAX_SUMMARY_ROWS`` (``truncated``); an ``archives`` line
        with ``view=summary``."""
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged['view'] = 'summary'
        self._require_instructor(request)
        reader = self._archives_reader()
        try:
            filters = parse_archive_filters(request.query, default_show=SHOW_STUDENT)
        except ValueError as e:
            return json_error(400, str(e))
        if not filters.get('lab'):
            return json_error(400, "a lab is expected")
        self._log_archive_filters(request, filters)
        if not await self._heavy_acquire():
            return json_error(503, "other reports are being computed, try again in a moment",
                              retry_after=HEAVY_RETRY_AFTER)
        try:
            page = await reader.summary(filters)
        except HistoryError as e:
            log.warning("archives database: a query failed: %s", e)
            return json_error(503, "the database of the archives does not answer")
        finally:
            self._heavy.release()
        return web.json_response({**page, 'limit': MAX_SUMMARY_ROWS, 'database': self.archives.status()})

    async def api_archive(self, request):
        """Instructors: one archived evaluation with its details (the elements with their raw
        titles, the parts, the errors); 404 when unknown."""
        self._require_instructor(request)
        reader = self._archives_reader()
        row_id = request.match_info['id']
        if not row_id.isdigit():
            return json_error(404, "unknown archive")
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged['archive_id'] = int(row_id)
        try:
            row = await reader.get(int(row_id))
        except HistoryError as e:
            log.warning("archives database: a query failed: %s", e)
            return json_error(503, "the database of the archives does not answer")
        if row is None:
            return json_error(404, "unknown archive")
        return web.json_response(row)

    async def api_archives_options(self, request):
        """Instructors: the labs and student groups the table knows (the suggestions of the
        filters of the Archives page)."""
        self._require_instructor(request)
        reader = self._archives_reader()
        try:
            options = await reader.options()
        except HistoryError as e:
            log.warning("archives database: a query failed: %s", e)
            return json_error(503, "the database of the archives does not answer")
        return web.json_response(options)

    # -- the user groups ----------------------------------------------------------------------------

    def _group_store(self):
        """The store of the custom groups, or 409 when the database is not configured."""
        store = self.memberships.store
        if store is None:
            raise PoolError(409, "the groups are not stored in a database ([access_log.database] of web.toml)")
        return store

    def _directory_status(self) -> dict:
        if self.memberships.directory is not None:
            return self.memberships.directory.status()
        return {'configured': False, 'loaded_at': None, 'error': self.cfg.group_directory_reason, 'people': 0}

    @staticmethod
    def _log_group(request, **fields):
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(fields)

    @staticmethod
    def _groups_db_error(e) -> web.Response:
        log.warning("groups database: %s", e)
        return json_error(503, "the database of the groups does not answer")

    async def _group_body(self, request) -> dict:
        try:
            body = await request.json()
        except ValueError:
            raise PoolError(400, "a JSON body is expected")
        if not isinstance(body, dict):
            raise PoolError(400, "a JSON object is expected")
        return body

    def _check_group_name(self, value) -> str:
        """A name for a custom group: 400 when malformed, 409 when a department or a directory
        group has it (the filters would be ambiguous)."""
        try:
            name = check_group_name(value)
        except ValueError as e:
            raise PoolError(400, str(e))
        if name in self.memberships.names_in_use():
            raise PoolError(409, f"a department or a directory group is named {name!r}")
        return name

    @staticmethod
    def _check_description(value) -> str:
        if value is None:
            return ''
        if not isinstance(value, str):
            raise PoolError(400, "the description must be a string")
        text = value.strip()
        if len(text) > MAX_DESCRIPTION:
            raise PoolError(400, f"the description is limited to {MAX_DESCRIPTION} characters")
        return text

    async def _resync_presentations(self):
        """After a change of the memberships: the connected users get the presentations their
        groups now include them in, or no longer."""
        with contextlib.suppress(Exception):
            await self.presentations.resync(self.presence.logins())

    async def api_groups(self, request):
        """Instructors: every group of every kind (the departments and the directory groups of
        the snapshot, the custom groups of the database) with its size, sorted by kind then name,
        plus the state of the directory read (``?refresh=1`` reads it again) and of the database
        (``null`` without one; the custom groups are missing when it does not answer, said by
        ``database.last_error``)."""
        self._require_instructor(request)
        refresh = request.query.get('refresh', '') in ('1', 'true')
        await self.memberships.refresh(force=refresh)
        groups = self.memberships.directory_groups()
        database = None
        store = self.memberships.store
        if store is not None:
            try:
                groups.extend(g.to_dict() for g in await store.list())
            except HistoryError as e:
                log.warning("groups database: a query failed: %s", e)
            database = store.status()
        groups.sort(key=group_sort_key)
        return web.json_response({'groups': groups, 'directory': self._directory_status(), 'database': database})

    async def api_groups_people(self, request):
        """Instructors: the people of the directory whose login or name contains ``?q=`` (at most
        ``MAX_PEOPLE``, ``more`` when cut), for the Add row of the Groups page; none without a
        directory."""
        self._require_instructor(request)
        await self.memberships.refresh()
        snapshot = self.memberships.snapshot()
        if snapshot is None:
            return web.json_response({'people': [], 'more': False})
        people, more = snapshot.search(request.query.get('q', '').strip())
        return web.json_response({'people': [{'login': p.login, 'fullname': p.fullname, 'group': p.group} for p in people],
                                  'more': more})

    async def api_group(self, request):
        """Instructors: one group with its members (login, full name and department from the
        directory; who added a member of a custom group and when); 404 when unknown."""
        self._require_instructor(request)
        kind, name = request.match_info['kind'], request.match_info['name']
        self._log_group(request, kind=kind, group=name)
        if kind not in KINDS:
            return json_error(404, "unknown group")
        await self.memberships.refresh()
        if kind == KIND_CUSTOM:
            store = self._group_store()
            try:
                group, members = await store.get(name)
            except GroupError as e:
                return json_error(e.status, str(e))
            except HistoryError as e:
                return self._groups_db_error(e)
            rows = [{**self.memberships.person_row(m['login']), 'added_by': m['added_by'], 'added_at': m['added_at']}
                    for m in members]
            return web.json_response({'group': group.to_dict(), 'members': rows})
        snapshot = self.memberships.snapshot()
        logins = snapshot.members_of(kind, name) if snapshot is not None else None
        if logins is None:
            return json_error(404, "unknown group")
        rows = [{**self.memberships.person_row(login), 'added_by': None, 'added_at': None} for login in sorted(logins)]
        return web.json_response({'group': group_dict(kind, name, len(logins)), 'members': rows})

    async def api_group_create(self, request):
        """Instructors: a new custom group (``name``, ``description``); 400 on a bad name, 409 when
        the name is taken (a custom group, a department or a directory group)."""
        identity = self._require_instructor(request)
        store = self._group_store()
        body = await self._group_body(request)
        wanted = body.get('name')
        self._log_group(request, action='create', group=wanted if isinstance(wanted, str) else None)
        await self.memberships.refresh()
        name = self._check_group_name(wanted)
        description = self._check_description(body.get('description'))
        self._log_group(request, group=name)
        try:
            group = await store.create(name, description, identity.login)
        except GroupError as e:
            return json_error(e.status, str(e))
        except HistoryError as e:
            return self._groups_db_error(e)
        await self.memberships.refresh()
        return web.json_response({'group': group.to_dict()}, status=201)

    async def api_group_update(self, request):
        """Instructors: rename a custom group and / or change its description (the keys given)."""
        self._require_instructor(request)
        store = self._group_store()
        name = request.match_info['name']
        body = await self._group_body(request)
        self._log_group(request, action='update', group=name)
        await self.memberships.refresh()
        new_name = None
        if body.get('name') is not None and body.get('name') != name:
            if isinstance(body.get('name'), str):
                self._log_group(request, new_name=body.get('name'))
            new_name = self._check_group_name(body.get('name'))
            self._log_group(request, new_name=new_name)
        description = self._check_description(body['description']) if 'description' in body else None
        try:
            group = await store.update(name, new_name=new_name, description=description)
        except GroupError as e:
            return json_error(e.status, str(e))
        except HistoryError as e:
            return self._groups_db_error(e)
        await self.memberships.refresh()
        await self._resync_presentations()
        return web.json_response({'group': group.to_dict()})

    async def api_group_delete(self, request):
        """Instructors: delete a custom group and its memberships."""
        self._require_instructor(request)
        store = self._group_store()
        name = request.match_info['name']
        self._log_group(request, action='delete', group=name)
        try:
            await store.delete(name)
        except GroupError as e:
            return json_error(e.status, str(e))
        except HistoryError as e:
            return self._groups_db_error(e)
        await self.memberships.refresh()
        await self._resync_presentations()
        return web.Response(status=204)

    async def _source_logins(self, store, source) -> tuple:
        """``(key, logins)`` of the group *source* (a key of any kind) named by an add or a removal
        of members: 400 when not a key, 404 when unknown; a ``HistoryError`` of the database
        propagates."""
        if not isinstance(source, str) or not source.strip():
            raise PoolError(400, "from must be a group key")
        kind, source_name = parse_group_key(source.strip())
        if kind == KIND_CUSTOM:
            try:
                _source_group, members = await store.get(source_name)
            except GroupError:
                raise PoolError(404, "unknown source group")
            return group_key(kind, source_name), sorted(m['login'] for m in members)
        snapshot = self.memberships.snapshot()
        found = snapshot.members_of(kind, source_name) if snapshot is not None else None
        if found is None:
            raise PoolError(404, "unknown source group")
        return group_key(kind, source_name), sorted(found)

    async def api_group_members_add(self, request):
        """Instructors: add ``logins`` to a custom group, or every member of the group ``from``
        (a key); the logins the directory does not know are refused as a whole (400 with
        ``unknown``) when the directory is loaded; ``added`` = the newcomers, ``members`` = the
        size afterwards."""
        identity = self._require_instructor(request)
        store = self._group_store()
        name = request.match_info['name']
        body = await self._group_body(request)
        self._log_group(request, action='add', group=name)
        await self.memberships.refresh()
        if 'from' in body:
            try:
                source, logins = await self._source_logins(store, body['from'])
            except HistoryError as e:
                return self._groups_db_error(e)
            self._log_group(request, source=source)
        else:
            logins = body.get('logins')
            if not isinstance(logins, list) or not all(isinstance(login, str) for login in logins):
                return json_error(400, "logins must be a list of logins")
            logins = [login.strip() for login in logins]
            if len(logins) > MAX_BATCH:
                return json_error(400, f"at most {MAX_BATCH} logins per call")
            bad = [login for login in logins if not is_valid_login(login)]
            if bad:
                return json_error(400, f"invalid login {bad[0]!r}")
            if self.memberships.knows_people():
                known = self.memberships.snapshot().people
                unknown = sorted({login for login in logins if login not in known})
                if unknown:
                    return json_error(400, "unknown logins", unknown=unknown)
        self._log_group(request, count=len(logins))
        try:
            added, members = await store.add_members(name, logins, identity.login)
        except GroupError as e:
            return json_error(e.status, str(e))
        except HistoryError as e:
            return self._groups_db_error(e)
        await self.memberships.refresh()
        await self._resync_presentations()
        return web.json_response({'added': added, 'members': members, 'unknown': []})

    async def api_group_members_remove(self, request):
        """Instructors: remove from a custom group every member who also belongs to the group
        ``?from=`` (a key of any kind; 400 without one, 404 when unknown); ``removed`` = the
        members taken out, ``members`` = the size afterwards."""
        self._require_instructor(request)
        store = self._group_store()
        name = request.match_info['name']
        self._log_group(request, action='remove', group=name)
        await self.memberships.refresh()
        try:
            source, logins = await self._source_logins(store, request.query.get('from'))
            self._log_group(request, source=source)
            removed, members = await store.remove_members(name, logins)
        except GroupError as e:
            return json_error(e.status, str(e))
        except HistoryError as e:
            return self._groups_db_error(e)
        self._log_group(request, count=removed)
        await self.memberships.refresh()
        await self._resync_presentations()
        return web.json_response({'removed': removed, 'members': members})

    async def api_group_member_remove(self, request):
        """Instructors: remove a member from a custom group (404 when not a member)."""
        self._require_instructor(request)
        store = self._group_store()
        name, login = request.match_info['name'], request.match_info['login']
        self._log_group(request, action='remove', group=name, member=login)
        if not is_valid_login(login):
            return json_error(404, f"{login!r} is not a member of {name!r}")
        try:
            await store.remove_member(name, login)
        except GroupError as e:
            return json_error(e.status, str(e))
        except HistoryError as e:
            return self._groups_db_error(e)
        await self.memberships.refresh()
        await self._resync_presentations()
        return web.Response(status=204)

    async def _heavy_acquire(self) -> bool:
        """A slot of the heavy reports (``HEAVY_QUERIES``), waited for ``heavy_wait`` seconds at
        most: ``False`` when none came free (the route answers 503); ``self._heavy.release()``
        once the report is done."""
        try:
            await asyncio.wait_for(self._heavy.acquire(), self.heavy_wait)
        except TimeoutError:
            return False
        return True

    async def api_history_statistics(self, request):
        """Administrators: the Statistics view of the History page (``accessstats``): who
        connected over the period of ``since`` / ``until`` (the last 24 hours by default; the
        login / address prefixes and the group apply) and for how long, per user, student group
        and lab, with the totals, from the rows of the database and the sessions still open.
        409 without a database like the events view.  A ``history`` line with
        ``view=statistics`` and the window resolved (``since_filter`` / ``until_filter``)."""
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged['view'] = 'statistics'
        self._require_administrator(request)
        if self.access.history is None:
            return json_error(409, "the connection log has no database ([access_log.database] of web.toml)")
        try:
            window = statistics_window(await self._resolve_group(parse_filters(request.query)), self.access.clock())
        except ValueError as e:
            return json_error(400, str(e))
        self._log_history_filters(logged, window)
        open_sessions = [session_of_visit(v) for v in self.access.visits.all() if visit_matches(v, window)]
        if not await self._heavy_acquire():
            return json_error(503, "other reports are being computed, try again in a moment",
                              retry_after=HEAVY_RETRY_AFTER)
        try:
            try:
                page = await self.access.history.query(statistics_query(window))
            except HistoryError as e:
                log.warning("access database: a history query failed: %s", e)
                return json_error(503, "the database of the connection log does not answer")
            stats = await asyncio.to_thread(compute_statistics, page['rows'], open_sessions, window['since'],
                                            window['until'])
        finally:
            self._heavy.release()
        return web.json_response({**stats, 'truncated': page['more'], 'limit': MAX_ROWS, **self._group_fields(window),
                                  'database': self.access.db.status() if self.access.db is not None else None})

    def _idle_timeout(self, identity: Identity) -> float:
        return self.cfg.pool.idle_timeout_anonymous if identity.anonymous else self.cfg.pool.idle_timeout_authenticated

    async def api_projects_create(self, request):
        identity = self._require_identity(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        if not isinstance(body, dict) or not isinstance(body.get('lab'), str):
            return json_error(400, "lab is required")
        wanted = body.get('host')             # an instructor's choice ('' = the automatic placement)
        if wanted is not None and not isinstance(wanted, str):
            return json_error(400, "host must be a host name")
        wanted = wanted or None
        logged = request.get(ACCESS_KEY)      # the line of the connection log: the lab, the host, the outcome
        if logged is not None:
            logged.update(lab=body['lab'], instructor=bool(body.get('instructor_mode')))
        if body.get('instructor_mode') and identity.role != ROLE_INSTRUCTOR:
            return json_error(403, "instructors only")
        if wanted and identity.role != ROLE_INSTRUCTOR:
            return json_error(403, "instructors only")
        # a student in an exam: its labs only, from the pre-start on, one project per lab (two
        # browsers of the student start the same lab); the agent gets the exam object
        exam_member = None
        if identity.role != ROLE_INSTRUCTOR:
            binding = self._exam_binding(identity)
            if binding is not None and logged is not None:
                logged.update(exam=binding[0].id)      # a refused start names the exam too
            self._exam_check(request, identity, lab=body['lab'])
            if binding is not None:
                exam = binding[0]
                running = await self.pool.projects_of(identity)
                if any(normal_lab(row.get('lab_name')) == body['lab'] for row in running):
                    return json_error(409, "a project of this lab is already running")
                exam_member = (exam, await self.exams.note_seen(exam, identity.login, self.access.address(request)))
        # The start slot of the user is taken now (two simultaneous starts of one user are refused)
        # and given back unless a start reached the agent and went past the flavor form: the form
        # of a lab with flavor_form_at_startup is fetched by a start that ends on it, and the
        # student's real start, seconds later, must not be refused; a placement refused by the
        # pool, an agent not answering or a relay broken before the result line cost nothing
        # either (the agent's start lock per user and max_projects still bound that user).
        limit_key = self._limit_key(request, identity)
        wait, previous = self.limiter.take_every('start', limit_key, self.cfg.limits.start_interval)
        if wait:
            return json_error(429, "please wait before starting another project", retry_after=round(wait))
        started = False
        reservation = None
        try:
            host, reservation = self.pool.pick(identity, wanted)
            if logged is not None:
                logged.update(host=host.name, placement=reservation.placement)
            payload = {'lab': body['lab'], 'idle_timeout': self._idle_timeout(identity)}
            if isinstance(body.get('flavor'), dict):
                payload['flavor_json'] = body['flavor']
            if body.get('instructor_mode'):
                payload['instructor_mode'] = True     # an instructor's own project in instructor mode
            if exam_member is not None:
                exam, member = exam_member
                payload['exam'] = exam_payload(exam, member, self.exams.clock())
                preset = exam.flavor_of(identity.login, body['lab'])
                if preset is not None:
                    payload['flavor'] = preset
                    payload.pop('flavor_json', None)
                payload['idle_timeout'] = self.cfg.exams.close_after    # counted from the end of the exam

            def on_result(obj: dict):
                nonlocal started
                started = obj.get('status') not in (RESULT_FLAVOR_FORM, RESULT_FLAVOR_ERROR)
                if logged is not None:
                    logged.update(result=obj.get('status'), rln=obj.get('running_lab_name'))
                if exam_member is not None and obj.get('status') == RESULT_CREATED and obj.get('running_lab_name'):
                    row = {'lab_name': body['lab'].replace('/', '@'), 'running_lab_name': obj['running_lab_name'],
                           'host': host.name, 'owner': identity.login}
                    asyncio.ensure_future(self._exam_project_created(exam_member[0], identity, [row]))

            return await self._forward_json(request, host, identity, payload, on_result=on_result)
        finally:
            if reservation is not None:
                self.pool.release(reservation)
            if not started:
                self.limiter.give_back('start', limit_key, previous)

    async def _forward_json(self, request, host, identity, payload: dict, *, on_result=None):
        """Relay a JSON POST that answers an NDJSON stream."""
        return await self.relay.forward_ndjson(request, host, identity, 'POST', '/projects',
                                               data=json.dumps(payload).encode('utf-8'),
                                               headers={'Content-Type': 'application/json'}, on_result=on_result)

    # -- one project -----------------------------------------------------------------------------

    def _path(self, rln: str, suffix: str = '') -> str:
        return f"/projects/{urllib.parse.quote(rln, safe='')}{suffix}"

    async def _relay_json(self, request, method: str, suffix: str = '', *, json_body=None, params=None, timeout=60.0):
        host, rln, identity = self._target(request)
        status, body = await self.relay.json(host, identity, method, self._path(rln, suffix), json=json_body,
                                             params=params, timeout=timeout)
        if status == 204:
            return web.Response(status=204)
        if isinstance(body, dict) and 'host' in body:
            body['host'] = host.name   # as the browser names it, not as the agent calls itself
        return web.json_response(body, status=status)

    async def _exam_project_created(self, exam: Exam, identity: Identity, rows: list):
        """A start of an exam project ended: recorded at once (the student's clock may start
        with it) and the agent told."""
        try:
            if await self.exams.observe(exam, identity.login, rows):
                await self._sync_exam_member(exam, exam.members[identity.login])
        except Exception:
            log.exception("exam %d: recording the new project of %s failed", exam.id, identity.login)

    async def api_project_get(self, request):
        return await self._relay_json(request, 'GET')

    async def api_project_close(self, request):
        identity = self._require_identity(request)
        if identity.role != ROLE_INSTRUCTOR:
            binding = self._exam_binding(identity)
            if binding is not None and lab_of_rln(request.match_info['rln']) in binding[0].lab_names(identity.login):
                raise ExamRefusal("an exam project cannot be closed during the exam")
        return await self._relay_json(request, 'DELETE', timeout=900)

    async def api_touch(self, request):
        return await self._relay_json(request, 'POST', '/touch')

    async def api_log(self, request):
        return await self._relay_json(request, 'GET', '/log', params={'offset': request.query.get('offset', '0')})

    async def api_schema(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.forward(request, host, identity, 'GET', self._path(rln, '/schema.svg'),
                                        params=dict(request.query))

    async def api_schema_pdf(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.forward(request, host, identity, 'GET', self._path(rln, '/schema.pdf'),
                                        params=dict(request.query))

    async def api_answers(self, request):
        if request.content_length and request.content_length > self.cfg.limits.max_answer_bytes:
            return json_error(413, "answers too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        return await self._relay_json(request, 'PUT', '/answers', json_body=body)

    async def api_evaluation(self, request):
        return await self._relay_json(request, 'GET', '/evaluation')

    def _limit_key(self, request, identity: Identity) -> str:
        """The key of the start / evaluation budget of a user: the login, or in anonymous mode
        the client address, since a new pseudonym costs one ``POST /login`` and would otherwise
        come with a fresh budget (the address is the one the login limit counts too)."""
        return identity.login if not identity.anonymous else 'addr:' + self.access.address(request)

    async def api_eval(self, request):
        identity = self._require_identity(request)
        wait = self.limiter.allow_every('eval', self._limit_key(request, identity), self.cfg.limits.eval_interval)
        if wait:
            return json_error(429, "please wait before evaluating again", retry_after=round(wait))
        return await self._relay_json(request, 'POST', '/eval', timeout=900)

    async def api_state(self, request):
        state = request.match_info['state']
        return await self._relay_json(request, 'POST', f"/states/{urllib.parse.quote(state, safe='')}", timeout=900)

    async def api_events(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.websocket(request, host, identity, self._path(rln, '/events'),
                                          upstream=request.get(SPECTATOR_KEY) is None)

    async def api_display(self, request):
        return await self._relay_json(request, 'GET', '/display')

    async def api_display_start(self, request):
        return await self._relay_json(request, 'POST', '/display', timeout=60)

    async def api_display_ws(self, request):
        host, rln, identity = self._target(request)
        # a spectator: the agent filters the RFB client messages (the handshake and the update
        # requests must still reach it, so the frames of the browser are forwarded)
        params = {'readonly': '1'} if request.get(SPECTATOR_KEY) is not None else None
        return await self.relay.websocket(request, host, identity, self._path(rln, '/display/ws'),
                                          protocols=(DISPLAY_SUBPROTOCOL,), params=params)

    async def api_terminal(self, request):
        host, rln, identity = self._target(request)
        device = request.match_info['device']
        params = {k: request.query[k] for k in ('cols', 'rows', 'join', 'private') if k in request.query}
        spectator = request.get(SPECTATOR_KEY) is not None
        if spectator:
            # a spectator only watches a live terminal of the presenter: the agent attaches a
            # read-only client, and nothing typed in the browser is relayed anyway
            if not params.get('join'):
                raise PoolError(403, "a spectator may only join a terminal")
            params.pop('private', None)
            params['readonly'] = '1'
        return await self.relay.websocket(request, host, identity,
                                          self._path(rln, f"/terminals/{urllib.parse.quote(device, safe='')}"),
                                          protocols=(TERMINAL_SUBPROTOCOL,), params=params, upstream=not spectator)

    # -- exams ------------------------------------------------------------------------------------
    # The state lives in ``exams.py`` (the database behind it in ``examstore.py``, the agents
    # told by ``examprojects.py``); here the student's own exam (what their browser shows) and
    # the API of the Exams page of the instructors.

    async def api_exam(self, request):
        """The exam binding the caller now (``null`` for an instructor or a student in none):
        the phase, the instants of the countdowns, the labs, whether their address is allowed;
        ``now`` is the portal's time (the browser computes its offset).  While the student's
        projects are being started, their rows are read here too (the clock starts once every
        lab has one)."""
        identity = self._require_identity(request)
        binding = self._exam_binding(identity)
        if binding is None:
            return web.json_response({'now': self.exams.clock(), 'exam': None})
        exam, member, phase = binding
        address = self.access.address(request)
        allowed = self.exams.address_allowed(exam, address)
        member = await self.exams.note_seen(exam, identity.login, address)
        if allowed and phase == PHASE_STARTING:
            rows = await self.pool.projects_of(identity)
            if await self.exams.observe(exam, identity.login, rows, address=address):
                await self._sync_exam_member(exam, member)
            phase = exam.phase(member, self.exams.clock())
        titles = await self._lab_titles(exam) if allowed else {}
        return web.json_response({'now': self.exams.clock(),
                                  'exam': self.exams.student_view(exam, member, phase, address=address, allowed=allowed,
                                                                  titles=titles)})

    async def api_exam_dismiss(self, request):
        """The student has seen the end banner of their exam: the usual pages come back."""
        identity = self._require_identity(request)
        exam = self._exam(request)
        try:
            phase = await self.exams.dismiss(exam.id, identity.login)
        except ValueError as e:
            raise PoolError(409, str(e))
        self._log_exam(request, exam=exam.id)
        return web.json_response({'ok': True, 'phase': phase})

    def _exam(self, request) -> Exam:
        exam = self.exams.get(request.match_info['id'])
        if exam is None:
            raise PoolError(404, "no such exam")
        return exam

    def _exam_store_required(self):
        if self.exams.store is None:
            raise PoolError(409, "the exams are not stored in a database ([access_log.database] of web.toml)")

    @staticmethod
    def _log_exam(request, **fields):
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(fields)

    @staticmethod
    def _exams_db_error(e) -> web.Response:
        log.warning("exams database: %s", e)
        return json_error(503, "the database of the exams does not answer")

    async def _known_labs(self, identity: Identity) -> set | None:
        """The names of the labs of the pool (the exam-only ones included) to check an exam
        against; ``None`` when no host answers (the exam is taken as it is, with a warning)."""
        labs = await self.pool.labs(identity, all_labs=True)
        if not labs:
            log.warning("exams: no host answers the lab list: the labs of the exam are not checked")
            return None
        return {e['name'] for e in labs if e.get('kind') == LAB_KIND_LAB}

    def _exam_summary(self, exam: Exam, now: float | None = None) -> dict:
        now = self.exams.clock() if now is None else now
        return exam.to_dict(now, len(self.exams.members_of(exam)))

    async def _exam_selection(self, exam: Exam, body: dict) -> set | None:
        """The students an action applies to: ``None`` for everybody, else the logins resolved
        now (400 when the selection is malformed or names somebody outside the audience)."""
        try:
            everybody, logins, groups = parse_selection(body)
            if everybody:
                return None
            await self.memberships.refresh()
            return self.exams.resolve(exam, logins, groups)
        except ValueError as e:
            raise PoolError(400, str(e))

    async def _sync_exam(self, exam: Exam, logins: set | None = None):
        for login in sorted(exam.members if logins is None else logins):
            member = exam.members.get(login)
            if member is not None:
                await self._sync_exam_member(exam, member)

    async def api_exams(self, request):
        """Instructors: every exam with its status and the size of its audience."""
        self._require_instructor(request)
        await self.memberships.refresh()
        now = self.exams.clock()
        store = self.exams.store
        return web.json_response({'exams': [self._exam_summary(e, now) for e in self.exams.listing()], 'now': now,
                                  'database': store.status() if store is not None else None})

    async def api_exam_create(self, request):
        identity = self._require_instructor(request)
        self._exam_store_required()
        self._log_exam(request, action='create')
        body = await self._group_body(request)
        try:
            spec = parse_exam(body, cfg=self.cfg.exams, now=self.exams.clock(),
                              known_labs=await self._known_labs(identity))
        except ValueError as e:
            raise PoolError(400, str(e))
        await self.memberships.refresh()
        try:
            exam = await self.exams.create(identity, spec)
        except HistoryError as e:
            return self._exams_db_error(e)
        self._log_exam(request, action='create', exam=exam.id, count=len(self.exams.members_of(exam)))
        return web.json_response(self._exam_summary(exam), status=201)

    async def api_exam_get(self, request):
        """Instructors: an exam and its students: the ones the portal can name (the explicit
        logins, the members of its groups, those it has seen), each with their phase, their
        clock, their adjustments and their running exam projects."""
        identity = self._require_instructor(request)
        exam = self._exam(request)
        await self.memberships.refresh()
        now = self.exams.clock()
        rows = await self.exam_projects.rows_of(exam, identity) if self.exam_projects is not None else {}
        members = []
        for login in sorted(self.exams.members_of(exam)):
            m = exam.members.get(login)
            connected = self.presence.identity_of(login)
            person = self.memberships.person_row(login)
            members.append({'login': login,
                            'fullname': connected.fullname if connected is not None else person.get('fullname', ''),
                            'group': connected.group if connected is not None else person.get('group', ''),
                            'connected': connected is not None, 'address': m.address if m is not None else '',
                            'phase': exam.phase(m, now), 'first_seen': m.first_seen if m is not None else None,
                            'started_at': m.started_at if m is not None else None, 'end_at': exam.end_at(m),
                            'ended_at': m.ended_at if m is not None else None,
                            'dismissed_at': m.dismissed_at if m is not None else None,
                            'extra_minutes': m.extra_minutes if m is not None else 0,
                            'labs': [l.to_dict() for l in exam.labs_of(login)], 'projects': rows.get(login, [])})
        return web.json_response({**self._exam_summary(exam, now), 'members': members, 'now': now})

    async def api_exam_update(self, request):
        """Instructors: the definition edited (the keys given replace the current ones; the
        students keep their clocks and adjustments)."""
        identity = self._require_instructor(request)
        self._exam_store_required()
        exam = self._exam(request)
        self._log_exam(request, action='update', exam=exam.id)
        body = await self._group_body(request)
        try:
            known = await self._known_labs(identity) if 'labs' in body else None
            spec = parse_exam(body, cfg=self.cfg.exams, now=self.exams.clock(), known_labs=known, current=exam)
        except ValueError as e:
            raise PoolError(400, str(e))
        await self.memberships.refresh()
        exam = await self.exams.update(exam.id, spec, resume='end_before' in body or 'duration' in body)
        await self._sync_exam(exam)
        self._log_exam(request, action='update', exam=exam.id, count=len(self.exams.members_of(exam)))
        return web.json_response(self._exam_summary(exam))

    async def api_exam_delete(self, request):
        """Instructors: the exam deleted; its projects become normal projects, or are closed
        with ``?close=1``."""
        self._require_instructor(request)
        exam = self._exam(request)
        self._log_exam(request, action='delete', exam=exam.id)
        closed = 0
        if self.exam_projects is not None:
            if request.query.get('close', '') in ('1', 'true'):
                closed = await self.exam_projects.close(exam, set(exam.members))
            else:
                await self.exam_projects.release(exam)
        await self.exams.delete(exam.id)
        self._log_exam(request, action='delete', exam=exam.id, count=closed)
        return web.json_response({'ok': True, 'closed': closed})

    async def api_exam_end(self, request):
        """Instructors: the exam over now, for everybody (no selection) or for the students
        selected."""
        self._require_instructor(request)
        exam = self._exam(request)
        self._log_exam(request, action='end', exam=exam.id)
        body = await self._group_body(request)
        logins = None if not body else await self._exam_selection(exam, body)
        exam = await self.exams.end_now(exam.id, logins)
        await self._sync_exam(exam, logins)
        self._log_exam(request, action='end', exam=exam.id, count=len(logins) if logins is not None else 0)
        return web.json_response(self._exam_summary(exam))

    async def api_exam_adjust(self, request):
        """Instructors: minutes added (or taken) to everybody or to the students selected."""
        self._require_instructor(request)
        exam = self._exam(request)
        self._log_exam(request, action='adjust', exam=exam.id)
        body = await self._group_body(request)
        try:
            minutes = parse_extra_minutes(body.get('extra_minutes'))
        except ValueError as e:
            raise PoolError(400, str(e))
        logins = await self._exam_selection(exam, body)
        exam = await self.exams.adjust(exam.id, logins, minutes)
        await self._sync_exam(exam, logins)
        self._log_exam(request, action='adjust', exam=exam.id, minutes=minutes,
                       count=len(logins) if logins is not None else 0)
        return web.json_response(self._exam_summary(exam))

    async def api_exam_labs(self, request):
        """Instructors: the labs changed for everybody or for the students selected (their
        browsers start the new ones; the projects of the labs dropped stay, as plain projects)."""
        identity = self._require_instructor(request)
        exam = self._exam(request)
        self._log_exam(request, action='labs', exam=exam.id)
        body = await self._group_body(request)
        try:
            labs = parse_labs(body.get('labs'), await self._known_labs(identity))
        except ValueError as e:
            raise PoolError(400, str(e))
        logins = await self._exam_selection(exam, body)
        exam = await self.exams.set_labs(exam.id, logins, labs)
        await self._sync_exam(exam, logins)
        self._log_exam(request, action='labs', exam=exam.id, count=len(logins) if logins is not None else 0)
        return web.json_response(self._exam_summary(exam))

    async def api_exam_close_projects(self, request):
        """Instructors: the exam projects of everybody or of the students selected closed."""
        self._require_instructor(request)
        exam = self._exam(request)
        self._log_exam(request, action='close', exam=exam.id)
        body = await self._group_body(request)
        logins = await self._exam_selection(exam, body)
        closed = 0
        if self.exam_projects is not None:
            closed = await self.exam_projects.close(exam, set(exam.members) if logins is None else logins)
        self._log_exam(request, action='close', exam=exam.id, count=closed)
        return web.json_response({'closed': closed})

    # -- presentations ----------------------------------------------------------------------------
    # An instructor's project shown read-only on the browsers of the chosen students: the state
    # lives in ``presentation.py``; here the page of a spectator, the presence sockets of every
    # page, and the API of the presenter's page.

    @staticmethod
    def _watcher(ws: web.WebSocketResponse) -> Watcher:
        async def close(code: int, reason: str):
            await ws.close(code=code, message=reason.encode('utf-8'))
        return Watcher(ws.send_json, close)

    def _presentation(self, request) -> Presentation:
        p = self.presentations.get(request.match_info['id'])
        if p is None:
            raise PoolError(404, "no such presentation")
        return p

    def _presenter_of(self, request) -> tuple:
        """``(identity, presentation)`` of a call reserved to the presenter."""
        identity = self._require_identity(request)
        p = self._presentation(request)
        if identity.login != p.presenter.login:
            raise PoolError(403, "the presenter only")
        return identity, p

    async def present_page(self, request):
        """The project page of a spectator: the same template as ``project_page`` with the
        ``presentation`` context (the browser hides every control and follows the presenter's
        view), shown in an iframe of the student's own page, hence the framing headers."""
        identity = request.get(IDENTITY_KEY)
        if not identity:
            raise web.HTTPFound('/login')
        p = self._presentation(request)
        await self.memberships.refresh()
        if not p.includes(identity):
            raise PoolError(403, "not in the audience")
        host = self.pool.host(p.host)
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=host.name, rln=p.rln, presenter=p.presenter.login)
        response = aiohttp_jinja2.render_template('project.html', request, self._page_context(
            request, host=host.name, rln=p.rln, api_base=f"/api/projects/{host.name}/{urllib.parse.quote(p.rln)}",
            presentation={'id': p.id, 'presenter': p.presenter.fullname or p.presenter.login}))
        response.headers['Content-Security-Policy'] = CSP_FRAMED
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return response

    async def api_presence_ws(self, request):
        """The socket every page of a logged-in user keeps open: the portal pushes the start and
        the end of the presentations the user is in; the frames of the browser are ignored."""
        identity = self._require_identity(request)
        page = request.query.get('page', '')
        if not (page.startswith('/') and len(page) <= MAX_PAGE_LENGTH and page.isprintable()):
            page = ''
        await self.memberships.refresh()        # the groups of the user, for the presentations including them
        ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=4096)
        await ws.prepare(request)
        watcher = self._watcher(ws)
        socket = self.presence.add(identity, page, watcher)
        try:
            await self.presentations.resync({identity.login})    # a presentation already running for them
            await self.focuses.resync({identity.login})          # a focus on them already
            await self.focuses.tell(identity.login, watcher)     # ... their other pages knew of
            await self.exams.resync({identity.login})            # an exam binding them already
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            self.presence.remove(socket)
            with contextlib.suppress(Exception):
                await self.presentations.resync({identity.login})
            with contextlib.suppress(Exception):
                await self.focuses.resync({identity.login})
            with contextlib.suppress(Exception):
                await self.exams.resync({identity.login})
        return ws

    async def api_presence(self, request):
        """Instructors: the connected users (the audience to choose from), with the keys of
        their groups."""
        identity = self._require_instructor(request)
        await self.memberships.refresh()
        return web.json_response(self.presence.connected(exclude_login=identity.login,
                                                         presentation_of=self.presentations.presentation_id_of,
                                                         groups_of=self.memberships.groups_of_identity))

    async def api_presentations(self, request):
        self._require_instructor(request)
        return web.json_response([p.to_dict(self.presence) for p in self.presentations.listing()])

    async def api_presentation_create(self, request):
        identity = self._require_instructor(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        if not isinstance(body, dict):
            return json_error(400, "a JSON object is expected")
        host = self.pool.host(str(body.get('host', '')))
        rln = body.get('rln')
        if not isinstance(rln, str) or running_lab_name_owner(rln) is None:
            return json_error(400, "bad running lab name")
        try:
            audience = parse_audience(body.get('audience'), identity.login)
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=host.name, rln=rln, audience=audience_size(audience))
        await self.memberships.refresh()
        p = await self.presentations.start(identity, host.name, rln, audience)
        return web.json_response(p.to_dict(self.presence), status=201)

    async def api_presentation_get(self, request):
        identity = self._require_identity(request)
        p = self._presentation(request)
        await self.memberships.refresh()
        if identity.login != p.presenter.login and not p.includes(identity):
            raise PoolError(403, "not in the audience")
        return web.json_response(p.to_dict(self.presence))

    async def api_presentation_audience(self, request):
        identity, p = self._presenter_of(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        try:
            audience = parse_audience((body or {}).get('audience') if isinstance(body, dict) else None, identity.login)
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=p.host, rln=p.rln, audience=audience_size(audience))
        await self.memberships.refresh()
        p = await self.presentations.set_audience(p.id, audience)
        return web.json_response(p.to_dict(self.presence))

    async def api_presentation_view(self, request):
        """The presenter's view (the active tab, the open terminals...), pushed to the spectators."""
        identity, p = self._presenter_of(request)
        if request.content_length and request.content_length > MAX_VIEW_BYTES + 64:
            return json_error(413, "view too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        view = body.get('view') if isinstance(body, dict) and 'view' in body else body
        try:
            await self.presentations.set_view(p.id, view)
        except ValueError as e:
            return json_error(400, str(e))
        except KeyError:
            return json_error(404, "no such presentation")
        return web.Response(status=204)

    async def api_presentation_evaluation(self, request):
        """The table of the presenter's Evaluation tab (header, rows, caption), pushed to the
        spectators as it is and sent to those attaching later."""
        identity, p = self._presenter_of(request)
        if request.content_length and request.content_length > MAX_EVALUATION_BYTES + 64:
            return json_error(413, "evaluation too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        evaluation = body.get('evaluation') if isinstance(body, dict) and 'evaluation' in body else body
        try:
            await self.presentations.set_evaluation(p.id, evaluation)
        except ValueError as e:
            return json_error(400, str(e))
        except KeyError:
            return json_error(404, "no such presentation")
        return web.Response(status=204)

    async def api_presentation_delete(self, request):
        identity = self._require_identity(request)
        p = self._presentation(request)
        if identity.login != p.presenter.login and identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "the presenter or an instructor only")
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=p.host, rln=p.rln, presenter=p.presenter.login)
        await self.presentations.end(p.id)
        return web.json_response({'ok': True})

    async def api_presentation_ws(self, request):
        """The socket of the presenter's page (the audience counts) and of a spectator's page
        (the view, at once and on every change); closed with ``WS_PRESENTATION_ENDED`` when the
        presentation is over, at once when it already is."""
        identity = self._require_identity(request)
        p = self.presentations.get(request.match_info['id'])
        ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=4096)
        if p is None:
            await ws.prepare(request)
            await ws.close(code=WS_PRESENTATION_ENDED, message=b"the presentation has ended")
            return ws
        presenter = identity.login == p.presenter.login
        if not presenter:
            await self.memberships.refresh()
            if not p.includes(identity):
                raise PoolError(403, "not in the audience")
        await ws.prepare(request)
        watcher = self._watcher(ws)
        if presenter:
            attached = await self.presentations.attach_presenter(p.id, watcher)
        else:
            attached = await self.presentations.attach_spectator(p.id, identity, watcher)
        if not attached:
            await ws.close(code=WS_PRESENTATION_ENDED, message=b"the presentation has ended")
            return ws
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            if presenter:
                self.presentations.detach_presenter(p.id, watcher)
            else:
                with contextlib.suppress(Exception):
                    await self.presentations.detach_spectator(p.id, identity.login, watcher)
        return ws

    # -- focus: an instructor on a student's project keeps the student's browser on it ---------
    # The registry is ``focus.Focuses``; the student's pages learn of a focus through the
    # presence socket (above), both pages share the view through the focus socket.

    def _focus(self, request) -> Focus:
        f = self.focuses.get(request.match_info['id'])
        if f is None:
            raise PoolError(404, "no such focus")
        return f

    def _focus_participant(self, request) -> tuple:
        """``(identity, focus)`` of a call reserved to the instructor or the student of it."""
        identity = self._require_identity(request)
        f = self._focus(request)
        if not f.participant(identity):
            raise PoolError(403, "the instructor or the student of this focus only")
        return identity, f

    async def api_focus_list(self, request):
        """The focuses of the caller: those they lead (an instructor's project pages resume
        theirs) and the one on them (a student's page)."""
        identity = self._require_identity(request)
        following = self.focuses.of_student(identity.login)
        return web.json_response({'leading': [f.to_dict() for f in self.focuses.for_instructor(identity.login)],
                                  'following': following.to_dict() if following is not None else None})

    async def api_focus_create(self, request):
        identity = self._require_instructor(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        if not isinstance(body, dict):
            return json_error(400, "a JSON object is expected")
        host = self.pool.host(str(body.get('host', '')))
        rln = body.get('rln')
        if not isinstance(rln, str) or running_lab_name_owner(rln) is None:
            return json_error(400, "bad running lab name")
        try:
            f = await self.focuses.start(identity, host.name, rln, body.get('view'))
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=host.name, rln=rln, student=f.student)
        return web.json_response(f.to_dict(), status=201)

    async def api_focus_get(self, request):
        _, f = self._focus_participant(request)
        return web.json_response(f.to_dict())

    async def api_focus_view(self, request):
        """The shared view (the active tab, the terminal shown, the question), from either
        page, pushed to both."""
        _, f = self._focus_participant(request)
        if request.content_length and request.content_length > MAX_VIEW_BYTES + 64:
            return json_error(413, "view too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        view = body.get('view') if isinstance(body, dict) and 'view' in body else body
        try:
            await self.focuses.set_view(f.id, view)
        except ValueError as e:
            return json_error(400, str(e))
        except KeyError:
            return json_error(404, "no such focus")
        return web.Response(status=204)

    async def api_focus_delete(self, request):
        identity = self._require_identity(request)
        f = self._focus(request)
        if identity.login != f.instructor.login and identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "the instructor of this focus or an instructor only")
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=f.host, rln=f.rln, instructor=f.instructor.login, student=f.student)
        await self.focuses.end(f.id)
        return web.json_response({'ok': True})

    async def api_focus_ws(self, request):
        """The socket of the instructor's page (the status of the student's page, the view) and
        of the student's page (the view, at once and on every change); closed with
        ``WS_FOCUS_ENDED`` when the focus is over, at once when it already is."""
        identity = self._require_identity(request)
        f = self.focuses.get(request.match_info['id'])
        ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=4096)
        if f is None:
            await ws.prepare(request)
            await ws.close(code=WS_FOCUS_ENDED, message=b"the focus has ended")
            return ws
        if not f.participant(identity):
            raise PoolError(403, "the instructor or the student of this focus only")
        leader = identity.login == f.instructor.login
        await ws.prepare(request)
        watcher = self._watcher(ws)
        if leader:
            attached = await self.focuses.attach_instructor(f.id, watcher)
        else:
            attached = await self.focuses.attach_student(f.id, identity, watcher)
        if not attached:
            await ws.close(code=WS_FOCUS_ENDED, message=b"the focus has ended")
            return ws
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            if leader:
                self.focuses.detach_instructor(f.id, watcher)
            else:
                with contextlib.suppress(Exception):
                    await self.focuses.detach_student(f.id, watcher)
        return ws
