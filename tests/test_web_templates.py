"""Tests of the browser side of the web front-end (``web/``): the Jinja2 templates render
without a server, reference existing static files, every ``_("...")`` string of the templates
and of the JavaScript has a French translation, and every JavaScript module parses.  The pure
modules (the lab tree, the group keys, the exam form, the terminal windows) run under node or bun,
or under bun in a container when the machine has neither (``SRE_TEST_JS``, below)."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
jinja2 = pytest.importorskip('jinja2', reason="jinja2 is not installed: the web front-end needs it: "
                              "run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / 'web'
TEMPLATES = WEB / 'templates'
STATIC = WEB / 'static'
JS = STATIC / 'js'
PO = ROOT / 'locale' / 'fr' / 'LC_MESSAGES' / 'sreweb.po'

#: SRE_TEST_JS: how the tests running a module of web/static/js (TestLabTreeOrder, TestGroupsModel,
#: TestExamsForm, TestTerminalGeometry) get a JavaScript runtime.  Unset: node, then bun, on the
#: PATH, the tests skipped without.  `docker` / `docker:<image>`: bun in a throwaway container of
#: the oven/bun image (pulled when missing), what the Makefile passes on a machine with neither
#: node nor bun; skipped without a reachable Docker daemon (root or the docker group).  Anything
#: else: the name on the PATH, or the path, of a runtime.
JS_RUNTIME_ENV = 'SRE_TEST_JS'
JS_DOCKER = 'docker'
JS_DOCKER_IMAGE = 'oven/bun:1-alpine'
JS_DOCKER_PULL_TIMEOUT = 600        # seconds: the image is 115 MB on disk
JS_DOCKER_PROBE_TIMEOUT = 30        # the daemon, the presence of the image, one run

#: the vendored files of `make xterm` / `make novnc` are not committed: a missing one is not an error here
VENDORED = ('vendor/xterm/', 'vendor/novnc/')

# _("...") / _('...') with the usual escapes, in a template or a JavaScript module
TRANSLATED_STRING = re.compile(r"""_\(\s*(['"])((?:\\.|(?!\1).)*)\1""")
STATIC_REFERENCE = re.compile(r"""['"(](/static/[^'")\s]+)""")
# the escapes of a .po string (and of the JavaScript / template literals checked against it)
PO_ESCAPE = re.compile(r'\\(.)')
PO_ESCAPES = {'n': '\n', 't': '\t', '"': '"', "'": "'", '\\': '\\'}

LANGUAGES = [('en', 'English'), ('fr', 'Français')]
IDENTITY = {'login': 'alice', 'fullname': 'Alice Martin', 'email': 'alice@example.org', 'role': 'student',
            'language': 'fr', 'anonymous': False, 'group': '', 'administrator': False}
RLN = '20261021153000@@@sre@dhcp.py@@@alice'
API_BASE = '/api/projects/a01/20261021153000%40%40%40sre%40dhcp.py%40%40%40alice'


def environment() -> jinja2.Environment:
    return jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), autoescape=True)


def context(**extra) -> dict:
    """The context of every page (``routes.Routes._page_context``) with the identity callable."""
    base = {'_': lambda text: text, 'identity': IDENTITY, 'auth_mode': 'anonymous', 'languages': LANGUAGES,
            'language': 'fr', 'instructor': False, 'administrator': False, 'groups': False, 'group_sources': False,
            'webconf': False, 'logout_url': '', 'site': {'name': '', 'url': '', 'logo_url': ''}}
    base.update(extra)
    return base


def render(name: str, **extra) -> str:
    return environment().get_template(name).render(context(**extra))


def static_references(html: str) -> list:
    return sorted(set(STATIC_REFERENCE.findall(html)))


def template_names() -> list:
    return sorted(p.name for p in TEMPLATES.glob('*.html'))


def js_modules() -> list:
    return sorted(JS.rglob('*.js'))


def parse_po(path: Path) -> dict:
    """``{msgid: msgstr}`` of a .po file (the multi-line strings joined, the escapes decoded)."""
    entries = {}
    msgid = msgstr = None
    current = None

    def decode(text: str) -> str:
        return PO_ESCAPE.sub(lambda m: PO_ESCAPES.get(m.group(1), m.group(1)), text)

    def flush():
        if msgid is not None:
            entries[msgid] = msgstr or ''

    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('msgid '):
            flush()
            msgid, msgstr, current = decode(line[6:].strip()[1:-1]), None, 'id'
        elif line.startswith('msgstr '):
            msgstr, current = decode(line[7:].strip()[1:-1]), 'str'
        elif line.startswith('"'):
            piece = decode(line[1:-1])
            if current == 'id':
                msgid += piece
            elif current == 'str':
                msgstr += piece
    flush()
    return entries


# ---------------------------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------------------------

class TestTemplates:
    def test_the_pages_exist(self):
        assert {'base.html', 'login.html', 'projects.html', 'open.html', 'project.html', 'watch.html',
                'pool.html', 'history.html', 'archives.html', 'groups.html', 'exams.html',
                'webconf_left.html'} <= set(template_names())

    @pytest.mark.parametrize('auth_mode', ['anonymous', 'ldap', 'proxy'])
    def test_login_page(self, auth_mode):
        html = render('login.html', identity=None, auth_mode=auth_mode, error='password')
        assert 'Wrong login or password.' in html
        if auth_mode == 'proxy':
            # the reverse proxy authenticates: no form, a message (the page is only seen on a misconfiguration)
            assert 'action="/login"' not in html and 'name="language"' not in html
            assert 'name="login"' not in html and 'display_name' not in html
            assert 'The web server passed no identity.' in html
        else:
            assert '<form method="post" action="/login">' in html
            assert 'name="language"' in html and 'value="fr" selected' in html
            if auth_mode == 'ldap':
                assert 'name="login"' in html and 'name="password"' in html and 'display_name' not in html
            else:
                assert 'name="display_name"' in html and 'name="password"' not in html
        # no session: the language links, no logout form
        assert 'action="/logout"' not in html and 'href="?lang=en"' in html
        assert '<script' not in html.split('<main')[0]   # the page works without JavaScript

    def test_logout_button(self):
        # proxy mode: the button only appears with a logout_url (the logout location or handler of the proxy)
        assert 'action="/logout"' in render('projects.html')
        assert 'action="/logout"' not in render('projects.html', auth_mode='proxy')
        assert 'action="/logout"' in render('projects.html', auth_mode='proxy', logout_url='/apache-logout')

    def test_logout_dialog(self):
        # the Logout button asks about the running projects (logout.js): the dialog goes with the form
        ids = ('id="logout-dialog"', 'id="logout-projects"', 'id="logout-cancel"', 'id="logout-keep"',
               'id="logout-close"')
        html = render('projects.html')
        assert all(i in html for i in ids) and 'closing in progress...' in html
        for html in (render('login.html', identity=None), render('projects.html', auth_mode='proxy')):
            assert not any(i in html for i in ids)
        assert 'id="logout-dialog"' in render('projects.html', auth_mode='proxy', logout_url='/apache-logout')

    def test_institution_next_to_the_brand(self):
        """[site] of web.toml: the institution's logo and name right after the SRE brand, on
        every page (the login page too), linked when a url is given."""
        site = {'name': 'IUT <Démo>', 'url': 'https://www.example.org/', 'logo_url': '/site/logo'}
        html = render('projects.html', site=site)
        assert html.index('class="brand"') < html.index('class="institution"') < html.index('class="topbar-nav"')
        assert 'href="https://www.example.org/"' in html and 'src="/site/logo"' in html
        assert 'IUT &lt;Démo&gt;' in html and 'IUT <Démo>' not in html
        html = render('login.html', identity=None, site=site)
        assert 'class="institution"' in html and 'src="/site/logo"' in html
        # the name alone, without link; the logo alone
        html = render('projects.html', site={'name': 'Demo', 'url': '', 'logo_url': ''})
        assert '<a class="institution">' in html and '<span>Demo</span>' in html and 'src="/site/logo"' not in html
        html = render('projects.html', site={'name': '', 'url': '', 'logo_url': '/site/logo'})
        assert 'src="/site/logo" alt=""' in html and '<span>' not in html.split('class="institution"')[1].split('</a>')[0]
        # nothing configured: no block at all
        assert 'institution' not in render('projects.html')

    def test_login_error_is_a_code_never_a_text(self):
        """The page shows its own message for a LOGIN_ERRORS code; a text in the URL (a phishing
        link ``?error=Your+account+is+locked…``, second Low finding of the security review) shows
        nothing, not even escaped."""
        html = render('login.html', identity=None, auth_mode='ldap', error='<script>alert(1)</script>')
        assert 'alert(1)' not in html and '&lt;script&gt;' not in html and 'class="error"' not in html
        html = render('login.html', identity=None, auth_mode='ldap', error='Your account is locked, call 0800')
        assert 'account is locked' not in html and 'class="error"' not in html
        for code, text in (('password', 'Wrong login or password.'),
                           ('rate_limited', 'Too many sign-in attempts: try again in a minute.'),
                           ('directory', 'The directory does not answer.')):
            html = render('login.html', identity=None, auth_mode='ldap', error=code)
            assert text in html and html.count('class="error"') == 1, code

    def test_projects_page(self):
        html = render('projects.html')
        assert 'Running projects' in html and 'href="/open"' in html
        assert 'id="projects"' in html and 'restore' not in html.lower()
        assert '/static/js/projects.js' in html
        # the logo of the empty page, hidden until the first answer of /api/projects
        assert '<div id="no-project" class="empty-logo" hidden>' in html
        assert '<img src="/static/img/sysreseval.svg"' in html
        assert 'Alice Martin' in html and 'action="/logout"' in html
        assert '<html lang="fr">' in html
        # the exam: the note above the cards and the progress of the automatic starts (projects.js)
        assert '<p id="exam-note" class="exam-note muted" hidden>' in html
        assert '<div id="exam-progress" class="progress-box" hidden>' in html

    def test_open_page(self):
        html = render('open.html')
        assert 'id="labs"' in html and 'id="start-button"' in html and '/static/js/open.js' in html
        assert 'name="mode"' not in html and 'href="/watch"' not in html and 'id="host"' not in html
        assert 'href="/pool"' not in html
        # the instructor's extras: the project mode radios (standard, instructor mode, debug mode) and
        # the Host select of the Open page, the Watch and Pool links of every page
        html = render('open.html', instructor=True)
        assert 'id="mode-standard" value="standard" checked' in html and 'id="mode-instructor"' in html
        assert 'id="mode-debug"' in html and 'Instructor mode' in html and 'Debug mode' in html
        assert 'href="/watch"' in html
        assert 'id="host"' in html and 'Automatic placement' in html and 'id="host-option" hidden' in html
        assert 'href="/pool"' in html
        html = render('projects.html', instructor=True)
        assert 'href="/watch"' in html and 'href="/pool"' in html and 'href="/history"' not in html
        assert 'href="/archives"' in html                  # the Archives link of every instructor
        assert 'href="/groups"' in html                    # the Groups link too, right after Watch
        assert 'href="/exams"' in html                     # and the Exams link, between Groups and Archives
        assert html.index('href="/watch"') < html.index('href="/groups"') < html.index('href="/exams"')
        assert html.index('href="/exams"') < html.index('href="/archives"')
        html = render('projects.html')
        assert 'href="/watch"' not in html and 'href="/pool"' not in html and 'href="/history"' not in html
        assert 'href="/archives"' not in html and 'href="/groups"' not in html and 'href="/exams"' not in html
        # the History link of the administrators (instructors)
        html = render('projects.html', instructor=True, administrator=True)
        assert 'href="/history"' in html and 'href="/watch"' in html

    def test_webconf_button_and_flags(self):
        """The Webconf button of the instructors, after the Pool link, when [bbb] is set; the
        body attributes every page carries for webconf.js and webconf_dialog.js; the page the
        BBB client lands on after Leave meeting."""
        html = render('projects.html', instructor=True, webconf=True)
        assert 'id="webconf-button"' in html and html.index('href="/pool"') < html.index('id="webconf-button"')
        assert 'data-webconf="true"' in html and 'data-fullname="Alice Martin"' in html and 'data-group-sources="false"' in html
        assert 'id="webconf-button"' not in render('projects.html', instructor=True)
        assert 'id="webconf-button"' not in render('projects.html', webconf=True)
        assert 'data-webconf="false"' in render('projects.html')
        assert 'data-group-sources="true"' in render('watch.html', instructor=True, group_sources=True)
        left = render('webconf_left.html', webconf_id='<r>', language='fr')
        assert '<html lang="fr">' in left and 'data-webconf-id="&lt;r&gt;"' in left and '/static/js/webconf_left.js' in left
        assert 'data-join-url="/api/webconfs/&lt;r&gt;/join"' in left and 'id="webconf-rejoin"' in left
        assert 'You have left the conference.' in left

    def test_watch_page(self):
        html = render('watch.html', instructor=True)
        assert 'id="watch"' in html and 'id="watch-filter"' in html and 'id="watch-count"' in html
        assert '/static/js/watch.js' in html and 'href="/watch"' in html
        for key in ('host', 'owner', 'fullname', 'group', 'title', 'started_at', 'last_eval', 'grade', 'mark', 'errors',
                    'auto_eval_count', 'terminals', 'managed'):
            assert f'data-sort="{key}"' in html, key
        assert 'data-sort="fullname">Name</th>' in html and 'colspan="14"' in html   # the full name as a column
        assert 'data-sort="auto_eval_count" title="The number of self-evaluations the student has run">Self-evaluations</th>' in html
        assert 'click a row for its last evaluation, a lab for the summary of the lab</span>' in html   # the dialogs
        assert 'a group for that summary' not in html
        assert 'data-login="alice"' in html
        # the group column and select exist, hidden without a configured group source: the column
        # needs a department source (groups), the select any source (group_sources: the custom
        # groups of the database, the directory groups)
        assert 'data-groups="false" data-group-sources="false"' in html and 'data-sort="group" hidden>' in html
        assert 'id="watch-group"' in html and 'data-kind="all"' in html and 'data-kind="none"' in html
        assert 'class="watch-group" title="Group" hidden>' in html
        shown = render('watch.html', instructor=True, groups=True, group_sources=True)
        assert 'data-groups="true" data-group-sources="true"' in shown and 'data-sort="group">' in shown
        assert 'a lab for the summary of the lab, a group for that summary restricted to the group</span>' in shown
        assert 'class="watch-group" title="Group">' in shown
        assert 'data-sort="group" hidden' not in shown and 'title="Group" hidden' not in shown
        select_only = render('watch.html', instructor=True, group_sources=True)
        assert 'class="watch-group" title="Group">' in select_only and 'data-sort="group" hidden>' in select_only

    def test_archives_page(self):
        """The Archives page of the instructors: the filters, the table (the Group column hidden
        unless a group source is configured), the pager, the summary container, the notice
        without a database."""
        html = render('archives.html', instructor=True, archives_database=False)
        assert 'id="archives"' in html and 'id="archives-filters"' in html and 'id="archives-count"' in html
        assert '/static/js/archives.js' in html and 'href="/archives"' in html and 'data-login="alice"' in html
        for name in ('student', 'group', 'lab', 'host', 'since', 'until', 'exam', 'show', 'limit'):
            assert f'name="{name}"' in html, name
        assert '<option value="project">The last evaluation of each project</option>' in html
        assert '<option value="student">The last evaluation of each student</option>' in html
        assert 'list="archives-labs"' in html and '<datalist id="archives-labs">' in html
        assert 'class="grid watch archives" data-database="false" data-groups="false"' in html
        assert 'id="archives-older"' in html and 'id="archives-newer"' in html and 'id="archives-reset"' in html
        assert 'data-view="evaluations" aria-pressed="true"' in html and 'data-view="summary" aria-pressed="false"' in html
        assert '<div id="archives-summary" class="archives-summary" hidden>' in html
        assert len(re.findall(r'<th[ >]', html)) == 13 and 'colspan="13"' in html
        assert '<th hidden>Group</th>' in html and '<label hidden>Group' in html
        assert 'id="archives-notice" class="muted">' in html and 'not stored in a database' in html
        # the selection and its reports: the checkbox column, the bar (hidden without a database)
        # with the three downloads and the options
        assert '<th class="select"><input type="checkbox" id="archives-select-all"' in html
        assert '<div id="archives-selection" class="selection-bar" hidden>' in html and 'id="archives-selected"' in html
        assert 'data-report="sheet" disabled' in html and 'data-report="outline" disabled' in html
        assert 'data-report="summary" disabled' in html and '>Summary spreadsheet</button>' in html
        assert '<details class="report-options">' in html
        for name, checked in (('all_evaluations', True), ('separate_instances', False), ('bonus_in_prefix', False),
                              ('timeline', True), ('remaining_time', False), ('parts', True)):
            assert f'<input type="checkbox" name="{name}"' + (' checked>' if checked else '>') in html, name
        with_db = render('archives.html', instructor=True, archives_database=True, groups=True)
        assert 'data-database="true" data-groups="true"' in with_db and 'id="archives-notice" class="muted" hidden>' in with_db
        assert '<th>Group</th>' in with_db and '<label>Group' in with_db and 'not stored in a database' not in with_db
        assert '<div id="archives-selection" class="selection-bar">' in with_db

    def test_archives_reports_script(self):
        """archives.js posts the selection to the report route and saves the answer as a file."""
        source = (ROOT / 'web' / 'static' / 'js' / 'archives.js').read_text(encoding='utf-8')
        assert "api.fetchRaw('POST', '/api/archives/report'" in source and 'URL.createObjectURL(blob)' in source
        assert "no_timeline: !ticked('timeline')" in source and "no_parts: !ticked('parts')" in source
        assert "event.target.closest('td.link, td.select')" in source and 'Content-Disposition' in source
        assert "summary: 'summary.ods'" in source

    def test_history_page(self):
        events = ('denied', 'login', 'start')
        html = render('history.html', instructor=True, administrator=True, history_database=False, events=events)
        assert 'id="history"' in html and 'id="history-filters"' in html and 'id="history-count"' in html
        assert '/static/js/history.js' in html and 'href="/history"' in html and 'data-login="alice"' in html
        for name in ('login', 'addr', 'group', 'event', 'host', 'rln', 'lab', 'since', 'until', 'limit'):
            assert f'name="{name}"' in html, name
        assert '<option value="start">start</option>' in html and '<option value="">All events</option>' in html
        # the Group select: every view, hidden with its label unless a source of user groups is
        # configured (the Watch page's rule), the "All groups" entry alone (the script adds the kinds)
        assert 'class="history-filters" data-group-sources="false"' in html
        assert '<label hidden>Group\n    <select name="group" id="history-group"' in html
        assert html.count('<option value="">All groups</option>') == 1
        with_sources = render('history.html', instructor=True, administrator=True, history_database=False, events=events,
                              group_sources=True)
        assert 'data-group-sources="true"' in with_sources and '<label hidden>' not in with_sources
        assert '<label>Group\n    <select name="group" id="history-group"' in with_sources
        assert 'type="datetime-local"' in html and 'class="grid watch history"' in html
        assert 'id="history-older"' in html and 'id="history-newer"' in html and 'id="history-reset"' in html
        # two tables: the events (shown, ten columns, every one a sortable header: table_sort.js
        # sorts the rows shown) and the sessions (hidden until chosen, eleven columns: ten sortable,
        # the Group one hidden unless a group source is configured, like the Watch page's, and the
        # Events link column), then the container of the statistics view
        events_table, rest = html.split('<table id="history-sessions"')
        sessions_table, statistics = rest.split('<div id="history-statistics"')
        assert 'id="history"' in events_table and 'class="grid watch history" data-database' in events_table
        assert events_table.count('<th class="sortable" data-sort="') == 10 and events_table.count('<th>') == 0
        assert events_table.count('colspan="10"') == 1
        for key, column in (('ts', 'Time'), ('event', 'Event'), ('login', 'Login'), ('addr', 'Address'), ('host', 'Host'),
                            ('rln', 'Project'), ('lab', 'Lab'), ('status', 'Status'), ('duration', 'Duration'),
                            ('details', 'Details')):
            assert f'<th class="sortable" data-sort="{key}">{column}</th>' in events_table, key
        assert sessions_table.startswith(' class="grid watch history sessions" data-groups="false" hidden>')
        assert sessions_table.count('<th class="sortable" data-sort="') == 10 and sessions_table.count('colspan="11"') == 1
        assert sessions_table.count('<th>') == 1 and '<th>Events</th>' in sessions_table
        assert '<th class="sortable" data-sort="group" hidden>Group</th>' in sessions_table
        for key, column in (('login', 'Login'), ('name', 'Name'), ('addr', 'Address'), ('start', 'Start time'),
                            ('end', 'End time'), ('duration', 'Duration'), ('requests', 'Requests'),
                            ('projects', 'Projects'), ('reason', 'Closed by')):
            assert f'<th class="sortable" data-sort="{key}">{column}</th>' in sessions_table, key
        assert sessions_table.index('>Name</th>') < sessions_table.index('Group') < sessions_table.index('>Address</th>')
        with_groups = render('history.html', instructor=True, administrator=True, history_database=False, events=events,
                             groups=True)
        with_groups_sessions = with_groups.split('<table id="history-sessions"')[1].split('<div id="history-statistics"')[0]
        assert with_groups_sessions.startswith(' class="grid watch history sessions" data-groups="true" hidden>')
        assert '<th class="sortable" data-sort="group">Group</th>' in with_groups_sessions
        assert ' hidden>Group</th>' not in with_groups
        # the view switch (Sessions first and pressed: the page opens on it), the filters of the
        # events view alone and the row count of the list views alone
        assert 'data-view="sessions" aria-pressed="true">Sessions<' in html
        assert 'data-view="events" aria-pressed="false">Events<' in html
        assert 'data-view="statistics" aria-pressed="false">Statistics<' in html
        assert html.index('data-view="sessions"') < html.index('data-view="events"') < html.index('data-view="statistics"')
        assert html.count('<label class="events-only">') == 4 and html.count('<label class="rows-only">') == 1
        assert 'For a session: the time it was closed' in html
        # the statistics view: hidden until chosen, the totals, the groups (hidden unless a group
        # source is configured, like the Group column of the users), the users and labs sortable,
        # the distribution; the headers translated by the template, the cells filled by the script
        assert statistics.startswith(' class="history-stats" data-groups="false" hidden>')
        for table_id in ('stats-totals', 'stats-groups', 'stats-users', 'stats-labs', 'stats-distribution'):
            assert f'<table id="{table_id}"' in statistics, table_id
        for key in ('period', 'users', 'students', 'instructors', 'groups', 'sessions', 'addresses', 'time', 'average',
                    'median', 'longest', 'peak', 'projects_started', 'projects_used', 'evaluations', 'page_time'):
            assert f'<td data-key="{key}"></td>' in statistics, key
        assert '<tr hidden><th>Groups</th>' in statistics and '<h2 hidden>Groups</h2>' in statistics
        assert '<table id="stats-groups" class="grid watch history stats" hidden>' in statistics
        assert '<th class="sortable" data-sort="group" hidden>Group</th>' in statistics
        assert '<th class="sortable" data-sort="time">Connection time</th>' in statistics          # the users
        assert '<th class="sortable" data-sort="time">On the project pages</th>' in statistics     # the labs
        assert '<th>Connection time</th>' in statistics and '<th>Time</th>' not in statistics      # never "Time" (a date)
        assert statistics.count('<th class="sortable" data-sort="lab">Lab</th>') == 1
        assert statistics.count('<tbody></tbody>') == 4
        statistics_with_groups = with_groups.split('<div id="history-statistics"')[1]
        assert statistics_with_groups.startswith(' class="history-stats" data-groups="true" hidden>')
        assert '<table id="stats-groups" class="grid watch history stats">' in statistics_with_groups
        assert '<th class="sortable" data-sort="group">Group</th>' in statistics_with_groups
        assert '<tr><th>Groups</th>' in statistics_with_groups and '<h2>Groups</h2>' in statistics_with_groups
        assert '<tr hidden>' not in statistics_with_groups and '<h2 hidden>' not in statistics_with_groups
        # without a database: the notice says what to configure, the table has nothing to show
        assert 'data-database="false"' in html and 'id="history-notice" class="muted">' in html
        assert 'not stored in a database' in html and 'access_log.database' in html
        with_db = render('history.html', instructor=True, administrator=True, history_database=True, events=events)
        assert 'data-database="true"' in with_db and 'id="history-notice" class="muted" hidden>' in with_db
        assert 'not stored in a database' not in with_db

    def test_pool_page(self):
        html = render('pool.html', instructor=True)
        assert 'id="pool"' in html and 'id="pool-filter"' in html and 'id="pool-count"' in html
        assert 'id="pool-status"' in html and '/static/js/pool.js' in html and 'href="/pool"' in html
        for key in ('name', 'state', 'projects', 'terminals', 'load1', 'occupied_by', 'uptime', 'sre_version'):
            assert f'data-sort="{key}"' in html, key
        assert 'data-login="alice"' in html and 'class="grid watch pool"' in html
        # the selection: the header checkbox, the bar of bulk buttons, one more column
        assert 'id="pool-select-all"' in html and 'id="pool-selection"' in html and 'id="pool-selected"' in html
        for action in ('enable', 'disable', 'wake', 'drain', 'poweroff'):
            assert f'data-action="{action}"' in html, action
        assert 'colspan="12"' in html and len(re.findall(r'<th[ >]', html)) == 12
        assert 'Host name: one or several words' in html

    def test_project_page(self):
        html = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=True)
        assert f'data-api-base="{API_BASE}"' in html
        assert 'data-rln="20261021153000@@@sre@dhcp.py@@@alice"' in html
        assert 'data-instructor="true"' in html
        assert 'id="tabbar"' in html and 'id="panes"' in html and 'id="closed-banner"' in html
        for control in ('instructor-toggle', 'wrap-toggle', 'font-minus', 'font-plus', 'schema-pdf-link',
                        'close-project'):
            assert f'id="{control}"' in html
        assert f'href="{API_BASE}/schema.pdf"' in html and 'Export Schema to PDF' in html
        assert f'{API_BASE}/export' not in html and f'{API_BASE}/save' not in html   # not offered on the web
        assert '/static/vendor/xterm/xterm.js' in html and '/static/vendor/xterm/addon-fit.js' in html
        assert '/static/vendor/xterm/xterm.css' in html and '/static/js/project.js' in html
        assert 'Instructor mode' in html
        # an instructor may present the project; a student has no such control
        for control in ('present', 'presentation-bar', 'presentation-edit', 'presentation-stop'):
            assert f'id="{control}"' in html, control
        assert 'Stop presenting' in html and 'data-group-sources="false"' in html and 'data-presentation' not in html
        # an instructor may focus the student on the project (the button is shown by project.js on
        # a student's project only); every page has the label of a followed student
        assert 'id="focus-student" class="toggle" aria-pressed="false" hidden' in html and 'Focus student on project' in html
        assert 'id="focus-label" class="presenter-name" hidden' in html
        student = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=False, group_sources=True)
        assert 'id="present"' not in student and 'id="presentation-bar"' not in student
        assert 'id="focus-student"' not in student and 'id="focus-label"' in student
        assert 'data-group-sources="true"' in student and 'id="close-project" class="danger">' in student

    def test_groups_page(self):
        """The Groups page of the instructors: the toolbar (filter, kind toggles, Refresh, New
        group), the hints of what is not configured, the table (the creator columns hidden without
        a database), the data attributes groups.js reads."""
        html = render('groups.html', instructor=True, groups_directory=False, groups_database=False)
        for element in ('groups', 'groups-filter', 'groups-kinds', 'groups-count', 'groups-refresh', 'groups-new',
                        'groups-hints', 'groups-notice', 'groups-status'):
            assert f'id="{element}"' in html, element
        for key in ('kind', 'name', 'members', 'created_by', 'created_at'):
            assert f'data-sort="{key}"' in html, key
        for kind in ('department', 'directory', 'custom'):
            assert f'data-kind="{kind}" aria-pressed="true"' in html, kind
        assert 'class="grid watch groups" data-directory="false" data-database="false"' in html
        assert len(re.findall(r'<th[ >]', html)) == 7 and 'colspan="7"' in html
        assert 'data-sort="created_by" hidden>' in html and 'data-sort="created_at" hidden>' in html
        assert 'id="groups-new" class="primary" hidden>' in html
        assert 'id="groups-hints" class="muted">' in html and '[auth.ldap]' in html and '[access_log.database]' in html
        assert 'id="groups-notice" class="muted" hidden>' in html and '/static/js/groups.js' in html
        assert 'href="/groups"' in html and 'href="/watch"' in html
        both = render('groups.html', instructor=True, groups_directory=True, groups_database=True)
        assert 'data-directory="true" data-database="true"' in both and 'id="groups-hints" class="muted" hidden>' in both
        assert 'id="groups-new" class="primary">' in both and 'data-sort="created_by">' in both
        assert 'data-sort="created_at">' in both and ' hidden>' not in both.split('<table')[1].split('</thead>')[0]
        directory_only = render('groups.html', instructor=True, groups_directory=True, groups_database=False)
        assert '[auth.ldap]' not in directory_only and '[access_log.database]' in directory_only
        assert 'id="groups-new" class="primary" hidden>' in directory_only

    def test_exams_page(self):
        """The Exams page of the instructors: the toolbar (filter, status toggles with the past
        exams hidden at first, New exam), the hints of what is missing, the table with the
        defaults exams.js reads, the detail section with its actions and the members table (the
        Group column hidden without a group source), the form dialog with every field."""
        defaults = {'lead': 10, 'pre_start': 5, 'eval_interval': 60}
        html = render('exams.html', instructor=True, exams_database=True, exams_available=True, exam_defaults=defaults)
        for element in ('exams', 'exams-filter', 'exams-status', 'exams-count', 'exams-new', 'exams-hints', 'exams-notice',
                        'exam-detail', 'exam-detail-title', 'exam-detail-summary', 'exam-detail-close', 'exam-detail-notice',
                        'exam-actions', 'exam-start-now', 'exam-end-now', 'exam-minutes', 'exam-extend-all', 'exam-reduce-all',
                        'exam-extend-selected', 'exam-reduce-selected', 'exam-end-selected', 'exam-labs-selected',
                        'exam-close-projects', 'exam-edit', 'exam-delete', 'exam-members', 'exam-select-all',
                        'exam-form', 'exam-form-title', 'exam-form-fields', 'exam-title', 'exam-logins', 'exam-groups',
                        'exam-labs', 'exam-start-after', 'exam-end-before', 'exam-duration', 'exam-lead', 'exam-pre-start',
                        'exam-eval-interval', 'exam-networks', 'exam-form-error', 'exam-form-cancel', 'exam-form-submit'):
            assert f'id="{element}"' in html, element
        for status, pressed in (('scheduled', 'true'), ('running', 'true'), ('past', 'false')):
            assert f'data-status="{status}" aria-pressed="{pressed}"' in html, status
        for key in ('title', 'status', 'start', 'end', 'duration', 'members', 'created_by'):
            assert f'data-sort="{key}"' in html, key
        assert ('class="grid watch exams" data-database="true" data-available="true" data-group-sources="false" '
                'data-lead="10" data-pre-start="5" data-eval-interval="60"') in html
        table, rest = html.split('<section id="exam-detail"')
        assert len(re.findall(r'<th[ >]', table)) == 10 and 'colspan="10"' in table
        detail, form = rest.split('<dialog id="exam-form"')
        assert detail.startswith(' class="exam-detail" hidden>')
        assert len(re.findall(r'<th[ >]', detail)) == 12 and 'colspan="12"' in detail
        assert 'data-sort="group" hidden>' in detail
        for key in ('login', 'fullname', 'group', 'connected', 'address', 'phase', 'started_at', 'end_at', 'extra_minutes'):
            assert f'data-sort="{key}"' in detail, key
        assert form.startswith(' class="modal exam">')
        assert 'type="datetime-local" id="exam-start-after"' in form and 'type="datetime-local" id="exam-end-before"' in form
        assert 'id="exam-groups" name="groups" multiple' in form and '<textarea id="exam-networks"' in form
        assert 'id="exams-new" class="primary">' in html and 'id="exams-hints" class="muted" hidden>' in html
        assert '/static/js/exams.js' in html and 'href="/exams"' in html and 'data-login="alice"' in html
        # without a database, or with anonymous users: no New exam button, the hint says why
        no_db = render('exams.html', instructor=True, exams_database=False, exams_available=True, exam_defaults=defaults)
        assert 'id="exams-new" class="primary" hidden>' in no_db and 'id="exams-hints" class="muted">' in no_db
        assert '[access_log.database]' in no_db and 'The users are anonymous' not in no_db and 'data-database="false"' in no_db
        anonymous = render('exams.html', instructor=True, exams_database=True, exams_available=False, exam_defaults=defaults)
        assert 'id="exams-new" class="primary" hidden>' in anonymous and 'The users are anonymous' in anonymous
        assert '[access_log.database]' not in anonymous and 'data-available="false"' in anonymous
        # the Group column of the members with a group source
        with_groups = render('exams.html', instructor=True, exams_database=True, exams_available=True,
                             exam_defaults=defaults, group_sources=True)
        assert 'data-group-sources="true"' in with_groups and 'data-sort="group">' in with_groups
        assert 'data-sort="group" hidden' not in with_groups

    def test_project_page_of_a_spectator(self):
        """The page in the iframe of /present/{id}: the data attributes project.js keys on, no
        control of the presenter's, no navigation out of the frame, the presenter named."""
        html = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=False,
                      presentation={'id': 'pres1', 'presenter': 'Pr. Of'})
        assert 'data-presentation="pres1"' in html and 'data-presenter="Pr. Of"' in html
        assert 'Presented by Pr. Of' in html and 'id="presenter-name"' in html and 'id="ended-banner"' in html
        assert 'id="close-project" class="danger" hidden>' in html
        assert 'id="present"' not in html and 'id="presentation-bar"' not in html and 'id="focus-student"' not in html
        assert 'href="/open"' not in html and 'href="/projects">Back' not in html
        assert 'id="tabbar"' in html and 'id="panes"' in html and '/static/js/project.js' in html
        # an instructor in the audience is a spectator like the others
        html = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=True,
                      presentation={'id': 'pres1', 'presenter': 'Pr. Of'})
        assert 'id="present"' not in html and 'id="presentation-bar"' not in html

    def test_project_page_escapes_the_presenter(self):
        html = render('project.html', host='a01', rln=RLN, api_base=API_BASE, presentation={'id': 'x', 'presenter': '<b>'})
        assert 'Presented by <b>' not in html and 'Presented by &lt;b&gt;' in html

    def test_project_page_escapes_the_name(self):
        html = render('project.html', host='a01', rln='x"<b>', api_base='/api/projects/a01/x%22%3Cb%3E', instructor=False)
        assert 'x"<b>' not in html and 'x&#34;&lt;b&gt;' in html

    def test_no_inline_script(self):
        """The CSP of the portal allows the scripts of /static only."""
        for name in template_names():
            text = (TEMPLATES / name).read_text(encoding='utf-8')
            for match in re.finditer(r'<script\b([^>]*)>(.*?)</script>', text, re.S):
                assert 'src=' in match.group(1) and not match.group(2).strip(), name
            assert not re.search(r'\son\w+\s*=', text), name   # no onclick="..."

    def test_static_references_exist(self):
        pages = [render('login.html', identity=None), render('projects.html'), render('open.html', instructor=True),
                 render('project.html', host='a01', rln=RLN, api_base=API_BASE), render('watch.html', instructor=True),
                 render('pool.html', instructor=True),
                 render('history.html', instructor=True, administrator=True, history_database=True, events=('login',)),
                 render('archives.html', instructor=True, archives_database=True),
                 render('groups.html', instructor=True, groups_directory=True, groups_database=True),
                 render('exams.html', instructor=True, exams_database=True, exams_available=True,
                        exam_defaults={'lead': 10, 'pre_start': 5, 'eval_interval': 60}),
                 render('project.html', host='a01', rln=RLN, api_base=API_BASE, presentation={'id': 'x', 'presenter': 'P'}),
                 render('webconf_left.html', webconf_id='r1')]
        # the image of the end overlay of an exam is referenced by exam.js, not by a template
        assert (STATIC / 'img' / 'thats_all_folks.svg').is_file()
        assert "'/static/img/thats_all_folks.svg'" in (JS / 'exam.js').read_text(encoding='utf-8')
        checked = 0
        for html in pages:
            references = static_references(html)
            assert references, "a page without any static file"
            for ref in references:
                relative = ref[len('/static/'):]
                if relative.startswith(VENDORED):
                    continue
                assert (STATIC / relative).is_file(), ref
                checked += 1
        assert checked >= 3

    def test_js_imports_exist(self):
        """Every relative import of a module names an existing module."""
        for module in js_modules():
            for match in re.finditer(r"""(?:import|from)\s+['"](\.{1,2}/[^'"]+)['"]""", module.read_text()):
                target = (module.parent / match.group(1)).resolve()
                assert target.is_file(), f"{module.name} imports {match.group(1)}"


# ---------------------------------------------------------------------------------------------
# translations
# ---------------------------------------------------------------------------------------------

class TestTranslations:
    def test_po_and_mo_exist(self):
        assert PO.is_file()
        assert PO.with_suffix('.mo').is_file(), "run msgfmt (make web-translations)"

    def test_every_string_of_the_templates_and_the_js_is_translated(self):
        entries = parse_po(PO)
        missing = set()
        found = 0
        sources = [TEMPLATES / name for name in template_names()] + js_modules()
        for source in sources:
            for match in TRANSLATED_STRING.finditer(source.read_text(encoding='utf-8')):
                text = PO_ESCAPE.sub(lambda m: PO_ESCAPES.get(m.group(1), m.group(1)), match.group(2))
                found += 1
                if not entries.get(text):
                    missing.add(text)
        assert found > 50
        assert not missing, f"untranslated: {sorted(missing)}"

    def test_placeholders_kept_in_translations(self):
        for msgid, msgstr in parse_po(PO).items():
            if not msgid:
                continue
            assert set(re.findall(r'\{\w+\}', msgid)) == set(re.findall(r'\{\w+\}', msgstr)), msgid

    def test_mo_matches_po(self):
        import gettext
        translation = gettext.translation('sreweb', localedir=str(ROOT / 'locale'), languages=['fr'])
        for msgid, msgstr in parse_po(PO).items():
            if msgid:
                assert translation.gettext(msgid) == msgstr, msgid


# ---------------------------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------------------------

_JS_RUNTIME: list = []      # the JsRuntime resolved once per session, or the reason of the skip


class JsRuntime:
    """What runs the ES modules of the tests below: node or bun of the machine, or bun in a
    container of the ``oven/bun`` image when the machine has none (``SRE_TEST_JS``, at the top)."""

    def __init__(self, executable: str, image: str | None = None):
        self.executable = executable        # node, bun, or the docker client
        self.image = image                  # the image of the container, None for a runtime of the machine

    @classmethod
    def resolve(cls) -> 'JsRuntime':
        """The runtime of the session, probed once (the daemon, the pull of the image); the test
        is skipped when there is none."""
        if not _JS_RUNTIME:
            _JS_RUNTIME.append(cls._resolve(os.environ.get(JS_RUNTIME_ENV, '')))
        if isinstance(_JS_RUNTIME[0], str):
            pytest.skip(_JS_RUNTIME[0])
        return _JS_RUNTIME[0]

    @classmethod
    def _resolve(cls, spec: str) -> 'JsRuntime | str':
        """The runtime ``spec`` (the value of SRE_TEST_JS) asks for, or the reason of the skip."""
        if spec == JS_DOCKER or spec.startswith(JS_DOCKER + ':'):
            return cls._docker(spec[len(JS_DOCKER) + 1:] or JS_DOCKER_IMAGE)
        for name in ([spec] if spec else ['node', 'bun']):
            executable = shutil.which(name)
            if executable:
                return cls(executable)
        if spec:
            return f"{JS_RUNTIME_ENV}={spec}: no such JavaScript runtime"
        return f"neither node nor bun is installed ({JS_RUNTIME_ENV}=docker runs bun in a container)"

    @classmethod
    def _docker(cls, image: str) -> 'JsRuntime | str':
        """Bun in a container of ``image``: the daemon probed, the image pulled when missing."""
        docker = shutil.which(JS_DOCKER)
        if docker is None:
            return f"{JS_RUNTIME_ENV}={JS_DOCKER}: docker is not installed"
        try:
            probe = subprocess.run([docker, 'version', '--format', '{{.Server.Version}}'],
                                   capture_output=True, text=True, timeout=JS_DOCKER_PROBE_TIMEOUT)
            if probe.returncode:
                return f"Docker daemon not reachable: {_last_line(probe.stderr)}"
            present = subprocess.run([docker, 'image', 'inspect', image], capture_output=True, text=True,
                                     timeout=JS_DOCKER_PROBE_TIMEOUT)
            if present.returncode:
                pull = subprocess.run([docker, 'pull', '--quiet', image], capture_output=True, text=True,
                                      timeout=JS_DOCKER_PULL_TIMEOUT)
                if pull.returncode:
                    return f"cannot pull {image}: {_last_line(pull.stderr)}"
        except subprocess.TimeoutExpired as e:
            return f"docker does not answer: {e}"
        return cls(docker, image)

    def run(self, directory: Path, script: str, *args: str) -> str:
        """The stdout of ``script``, an ES module of ``directory``, run with ``args``."""
        if self.image is None:
            argv = [self.executable, str(directory / script), *args]
        else:
            # the caller's uid: pytest creates the directory with mode 0700 and the image would run
            # as its own user `bun`; a writable HOME for the runtime; no network: the modules import
            # nothing but each other
            argv = [self.executable, 'run', '--rm', '--network', 'none', '--user', f'{os.getuid()}:{os.getgid()}',
                    '--env', 'HOME=/tmp', '--volume', f'{directory}:/work:ro', '--workdir', '/work',
                    self.image, 'bun', script, *args]
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=JS_DOCKER_PROBE_TIMEOUT)
        if completed.returncode:
            pytest.fail(f"{script} exited {completed.returncode}:\n{completed.stderr}")
        return completed.stdout


def _last_line(text: str) -> str:
    """The last line of a docker error, up to its first `; ` (the hints of the client)."""
    lines = text.strip().splitlines()
    return lines[-1].split('; ')[0] if lines else ''


@pytest.fixture
def js() -> JsRuntime:
    """The JavaScript runtime of the session (skips the test without one)."""
    return JsRuntime.resolve()


def js_project(directory: Path, runner: str, *modules: str) -> str:
    """``modules`` of web/static/js copied into ``directory`` next to ``run.mjs`` = ``runner`` and
    the package.json making them ES modules; returns the name of the runner."""
    for name in modules:
        shutil.copy(JS / name, directory / name)
    (directory / 'package.json').write_text('{"type": "module"}\n')
    (directory / 'run.mjs').write_text(runner)
    return 'run.mjs'


class TestJsRuntime:
    """The resolution of SRE_TEST_JS and the command lines (Docker itself is never called)."""

    def test_resolution(self, monkeypatch):
        found = {'node': '/usr/bin/node', 'bun': '/usr/local/bin/bun', 'docker': '/usr/bin/docker'}
        monkeypatch.setattr(shutil, 'which', lambda name: found.get(name))
        assert JsRuntime._resolve('').executable == '/usr/bin/node'
        assert JsRuntime._resolve('bun').executable == '/usr/local/bin/bun'
        assert JsRuntime._resolve('deno') == 'SRE_TEST_JS=deno: no such JavaScript runtime'
        found.pop('node')
        assert JsRuntime._resolve('').executable == '/usr/local/bin/bun'
        found.pop('bun')
        assert JsRuntime._resolve('') == ('neither node nor bun is installed '
                                          '(SRE_TEST_JS=docker runs bun in a container)')
        found.pop('docker')
        assert JsRuntime._resolve('docker') == 'SRE_TEST_JS=docker: docker is not installed'
        images = []
        monkeypatch.setattr(JsRuntime, '_docker',
                            classmethod(lambda cls, image: images.append(image) or cls('/usr/bin/docker', image)))
        assert JsRuntime._resolve('docker').image == JS_DOCKER_IMAGE
        assert JsRuntime._resolve('docker:oven/bun:1-slim').image == 'oven/bun:1-slim'
        assert images == [JS_DOCKER_IMAGE, 'oven/bun:1-slim']

    def test_command_lines(self, monkeypatch, tmp_path):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout='"ok"', stderr='')

        monkeypatch.setattr(subprocess, 'run', fake_run)
        assert JsRuntime('/usr/bin/node').run(tmp_path, 'run.mjs', 'a', 'b') == '"ok"'
        assert calls[0] == ['/usr/bin/node', str(tmp_path / 'run.mjs'), 'a', 'b']
        assert JsRuntime('/usr/bin/docker', 'oven/bun:1-alpine').run(tmp_path, 'run.mjs', 'a') == '"ok"'
        argv = calls[1]
        assert argv[:3] == ['/usr/bin/docker', 'run', '--rm']
        assert argv[-4:] == ['oven/bun:1-alpine', 'bun', 'run.mjs', 'a']      # the runner relative to /work
        assert argv[argv.index('--user') + 1] == f'{os.getuid()}:{os.getgid()}'
        assert argv[argv.index('--volume') + 1] == f'{tmp_path}:/work:ro'
        assert argv[argv.index('--network') + 1] == 'none'

    def test_failure_reported_with_stderr(self, monkeypatch, tmp_path):
        monkeypatch.setattr(subprocess, 'run',
                            lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout='', stderr='boom'))
        with pytest.raises(pytest.fail.Exception, match='run.mjs exited 1:\nboom'):
            JsRuntime('/usr/bin/node').run(tmp_path, 'run.mjs')


#: what GET /api/labs gives: the root in the "title" mode (its directories first by label, then
#: its labs by label, accents and case ignored, "TP 2" before "TP 10"), z in the "manual" mode
#: (the order of the CLI kept), a without title; the titles resolve to English (init() never ran)
LAB_TREE_IN = [
    {'name': 'tp10.py', 'title': 'TP 10', 'kind': 'lab', 'sort': 'title'},
    {'name': 'z', 'title': {'en': 'Zone', 'fr': 'La zone'}, 'kind': 'dir', 'sort': 'title'},
    {'name': 'z/b.py', 'title': None, 'kind': 'lab', 'sort': 'manual'},
    {'name': 'z/a.py', 'title': 'Alpha', 'kind': 'lab', 'sort': 'manual'},
    {'name': 'a', 'title': None, 'kind': 'dir', 'sort': 'title'},
    {'name': 'a/x.py', 'title': None, 'kind': 'lab', 'sort': 'name'},
    {'name': 'tp2.py', 'title': 'TP 2', 'kind': 'lab', 'sort': 'title'},
    {'name': 'e.py', 'title': {'en': 'Study', 'fr': 'Étude'}, 'kind': 'lab', 'sort': 'title'},
    {'name': 'f.py', 'title': 'Étude', 'kind': 'lab', 'sort': 'title'},
    {'name': 'arp.py', 'title': None, 'kind': 'lab', 'sort': 'title'},
]
#: [name, label, titled, children] per directory, [name, label, titled] per lab
LAB_TREE_OUT = [
    ['a', 'a', False, [['a/x.py', 'x', False]]],
    ['z', 'Zone', True, [['z/b.py', 'b', False], ['z/a.py', 'Alpha', True]]],
    ['arp.py', 'arp', False], ['f.py', 'Étude', True], ['e.py', 'Study', True],
    ['tp2.py', 'TP 2', True], ['tp10.py', 'TP 10', True],
]
LAB_TREE_RUNNER = """\
import {labTree} from './tree.js';

const outline = (node) => [
  ...node.dirs.map((dir) => [dir.name, dir.label, dir.titled, outline(dir)]),
  ...node.leaves.map((leaf) => [leaf.name, leaf.label, leaf.titled]),
];
process.stdout.write(JSON.stringify(outline(labTree(JSON.parse(process.argv[2]), process.argv[3]))));
"""


class TestLabTreeOrder:
    """``labTree()`` of tree.js run by the ``js`` runtime (node, bun, or bun in a container:
    SRE_TEST_JS), skipped without one: the Open page keeps the order of the CLI but for the
    "title" mode, sorted by label."""

    def test_order(self, tmp_path, js):
        runner = js_project(tmp_path, LAB_TREE_RUNNER, 'tree.js', 'i18n.js', 'ui.js')
        assert json.loads(js.run(tmp_path, runner, json.dumps(LAB_TREE_IN), 'fr')) == LAB_TREE_OUT


GROUPS_MODEL_RUNNER = """\
import {parseKey, normalizeKey, rowGroupKeys, rowMatchesGroup, sortGroups} from './groups_model.js';

const rows = JSON.parse(process.argv[2]);
const keys = [null, '', '1A', 'department:1A', 'custom:Project X', 'department:2B'];
const groups = [{kind: 'custom', name: 'b'}, {kind: 'department', name: '2A'}, {kind: 'directory', name: 'x'},
                {kind: 'department', name: '1A'}, {kind: 'custom', name: 'A'}, {kind: 'custom', name: 'a10'},
                {kind: 'custom', name: 'a9'}];
process.stdout.write(JSON.stringify({
  parsed: ['custom:a:b', '1A', 'nope:x', 'department:1A', ''].map(parseKey),
  normalized: ['1A', 'custom:x', 'directory:y:z'].map(normalizeKey),
  keys: rows.map((row) => [...rowGroupKeys(row)]),
  matches: keys.map((key) => rows.map((row) => rowMatchesGroup(row, key))),
  byKind: sortGroups(groups).map((g) => `${g.kind}:${g.name}`),
  byNameDesc: sortGroups(groups, {key: 'name', asc: false}).map((g) => g.name),
}));
"""
GROUPS_MODEL_ROWS = [{'group': '1A', 'groups': ['department:1A', 'directory:students', 'custom:Project X']},
                     {'group': '', 'groups': []}, {'group': '2B'}]
GROUPS_MODEL_OUT = {
    'parsed': [{'kind': 'custom', 'name': 'a:b'}, {'kind': 'department', 'name': '1A'},
               {'kind': 'department', 'name': 'nope:x'}, {'kind': 'department', 'name': '1A'},
               {'kind': 'department', 'name': ''}],
    'normalized': ['department:1A', 'custom:x', 'directory:y:z'],
    'keys': [['department:1A', 'directory:students', 'custom:Project X'], [], ['department:2B']],
    'matches': [[True, True, True], [False, True, False], [True, False, False], [True, False, False],
                [True, False, False], [False, False, True]],
    'byKind': ['department:1A', 'department:2A', 'directory:x', 'custom:A', 'custom:a9', 'custom:a10', 'custom:b'],
    'byNameDesc': ['x', 'b', 'a10', 'a9', 'A', '2A', '1A'],
}


class TestGroupsModel:
    """groups_model.js (the keys of the user groups shared by the Groups, Watch and project pages)
    run by the ``js`` runtime, skipped without one."""

    def test_keys_and_matching(self, tmp_path, js):
        runner = js_project(tmp_path, GROUPS_MODEL_RUNNER, 'groups_model.js', 'i18n.js')
        assert json.loads(js.run(tmp_path, runner, json.dumps(GROUPS_MODEL_ROWS))) == GROUPS_MODEL_OUT


LAB_KEY_RUNNER = """\
import {labKey} from './lab_key.js';

process.stdout.write(JSON.stringify(JSON.parse(process.argv[2]).map(labKey)));
"""


class TestLabKey:
    """lab_key.js: the key the Watch and Archives summaries group the projects of a lab by (the
    file really run, else the lab name of the row), run by the ``js`` runtime, skipped without one."""

    def test_fallbacks(self, tmp_path, js):
        runner = js_project(tmp_path, LAB_KEY_RUNNER, 'lab_key.js')
        rows = [{'canonical_lab': 'sre@dns1.py', 'lab_name': 's3@r306@dns1.py'},     # a Watch row
                {'lab_name': 's3@r306@dns1.py'},                                     # an older agent
                {'canonical_lab': 'sre/dns1.py', 'lab': 's3/r306/dns1.py'},          # an archives row
                {'lab': 's3/r306/dns1.py'}, {'canonical_lab': ''}, {}, None]
        assert json.loads(js.run(tmp_path, runner, json.dumps(rows))) == \
            ['sre@dns1.py', 's3@r306@dns1.py', 'sre/dns1.py', 's3/r306/dns1.py', '', '', '']


EXAMS_FORM_RUNNER = """\
import {toLocalInput, fromLocalInput, labsText, labLabel} from './exams_form.js';

const epochs = JSON.parse(process.argv[2]);
process.stdout.write(JSON.stringify({
  roundTrip: epochs.map((e) => fromLocalInput(toLocalInput(e))),
  shape: epochs.map((e) => /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$/.test(toLocalInput(e))),
  empty: [toLocalInput(null), toLocalInput('x'), fromLocalInput(''), fromLocalInput('nope')],
  labs: labsText([{lab: 'sre/dhcp.py', flavor: null}, {lab: 'sre/_EXAM_/x.py', flavor: 'hard'}]),
  labels: [labLabel({name: 'sre/dhcp.py', title: {en: 'DHCP lab', fr: 'TP DHCP'}}), labLabel({name: 'sre/dhcp.py', title: null})],
}));
"""


class TestExamsForm:
    """The conversions of exams_form.js (the datetime-local inputs of the exam form, the lab
    texts) run by the ``js`` runtime, skipped without one."""

    def test_conversions(self, tmp_path, js):
        runner = js_project(tmp_path, EXAMS_FORM_RUNNER,
                            'exams_form.js', 'i18n.js', 'ui.js', 'login_picker.js', 'api.js', 'groups_model.js')
        epochs = [1792999980, 1793005440, 0]      # whole minutes: the inputs carry no seconds
        out = json.loads(js.run(tmp_path, runner, json.dumps(epochs)))
        assert out['roundTrip'] == epochs and out['shape'] == [True, True, True]
        assert out['empty'] == ['', '', None, None]
        assert out['labs'] == 'sre/dhcp.py, sre/_EXAM_/x.py:hard'
        assert out['labels'] == ['DHCP lab', 'sre/dhcp']


WEBCONF_MODEL_RUNNER = """\
import * as M from './webconf_model.js';

const push = {t: 'webconf', id: 'r1', name: 'Salle 1', owner: {login: 'prof', fullname: 'Pr. Of'}, role: 'viewer',
              join_url: '/api/webconfs/r1/join'};
const room = M.roomOf(push);
const bad = [M.roomOf(null), M.roomOf({t: 'webconf', id: 'r1'}), M.roomOf({id: 'r1', join_url: 'https://evil/join'}),
             M.roomOf({id: '', join_url: '/api/webconfs/x/join'})];
const s0 = M.nextState(null, {type: 'push', room, stored: null});
const again = M.nextState(s0, {type: 'push', room: {...room, name: 'Renamed'}, stored: null});
const stored = {id: 'r1', mode: 'tab', fractions: {x: 0.1, y: 0.2, w: 0.5, h: 0.4}};
const restored = M.nextState(null, {type: 'push', room, stored});
const otherStored = M.nextState(null, {type: 'push', room, stored: {...stored, id: 'r2'}});
const steps = [];
let s = s0;
for (const type of ['minimize', 'restore', 'dock', 'undock', 'full', 'window', 'leave', 'window', 'popout', 'left-page',
                    'window', 'minimize', 'dock', 'minimize', 'full', 'leave', 'leave', 'dock']) {
  s = M.nextState(s, {type});
  steps.push(s.mode);
}
const moved = M.nextState(s0, {type: 'moved', fractions: {x: 0.1, y: 0.1, w: 0.3, h: 0.3}});
const movedMinimized = M.nextState(M.nextState(s0, {type: 'minimize'}), {type: 'moved', fractions: {x: 0.1, y: 0.1, w: 0.3, h: 0.3}});
process.stdout.write(JSON.stringify({
  room, bad, s0, againName: again.name, againMode: again.mode, restoredMode: restored.mode,
  restoredFractions: restored.fractions, otherStoredMode: otherStored.mode, steps,
  movedFractions: moved.fractions, movedMinimizedFractions: movedMinimized.fractions,
  badMoveSame: M.nextState(s0, {type: 'moved', fractions: {x: 2, y: 0, w: 1, h: 1}}) === s0,
  ended: M.nextState(s0, {type: 'ended', id: 'r1'}), endedOtherSame: M.nextState(s0, {type: 'ended', id: 'r2'}) === s0,
  unknownSame: M.nextState(s0, {type: 'bogus'}) === s0, nullSame: M.nextState(s0, null) === s0,
  fromNothing: M.nextState(null, {type: 'dock'}),
  effective: [M.effectiveMode(restored, {hasTabHost: true}), M.effectiveMode(restored, {hasTabHost: false}),
              M.effectiveMode(s0, {}), M.effectiveMode(null, {})],
  parsed: [M.parseStored(null, 1000), M.parseStored('garbage', 1000),
           M.parseStored(JSON.stringify({id: 'r1', mode: 'flying', t: 900}), 1000),
           M.parseStored(JSON.stringify({id: 'r1', mode: 'window', t: 900, fractions: {x: 5}}), 1000),
           M.parseStored(JSON.stringify({id: 'r1', mode: 'tab', t: 1000 - M.STORED_MAX_AGE}), 1000),
           M.parseStored(JSON.stringify(M.storedOf(moved, 900)), 1000)],
  storedNull: M.storedOf(null, 1), storedOf: M.storedOf(moved, 42),
  sizes: [M.defaultWindowSize({width: 1600, height: 1000}), M.defaultWindowSize({width: 800, height: 600}),
          M.defaultWindowSize({width: 300, height: 200})],
  fractions: M.defaultWindowFractions({width: 1600, height: 1000}), noArea: M.defaultWindowFractions({width: 0, height: 0}),
  full: M.fullRect({width: 1280, height: 720}, 32), fullTiny: M.fullRect({width: 100, height: 10}, 32),
  live: M.MODES.map(M.isLive),
}));
"""


class TestWebconfModel:
    """The pure model of the web conference shown by a page (webconf_model.js: the room of a
    push, the modes and their transitions, the stored state, the default geometry), run by the
    ``js`` runtime, skipped without one."""

    def test_model(self, tmp_path, js):
        runner = js_project(tmp_path, WEBCONF_MODEL_RUNNER, 'webconf_model.js', 'terminal_windows.js', 'i18n.js', 'ui.js')
        out = json.loads(js.run(tmp_path, runner))
        room = {'id': 'r1', 'name': 'Salle 1', 'owner': {'login': 'prof', 'fullname': 'Pr. Of'}, 'role': 'viewer',
                'joinUrl': '/api/webconfs/r1/join'}
        assert out['room'] == room and out['bad'] == [None] * 4
        assert out['s0'] == {**room, 'mode': 'window', 'fractions': None}
        assert (out['againName'], out['againMode']) == ('Renamed', 'window')          # the same room: the mode kept
        assert out['restoredMode'] == 'tab' and out['restoredFractions'] == {'x': 0.1, 'y': 0.2, 'w': 0.5, 'h': 0.4}
        assert out['otherStoredMode'] == 'window'                                     # another room's state
        assert out['steps'] == ['minimized', 'window', 'tab', 'window', 'full', 'window', 'left', 'window', 'popout',
                                'left', 'window', 'minimized', 'tab', 'tab', 'full', 'left', 'left', 'left']
        assert out['movedFractions'] == {'x': 0.1, 'y': 0.1, 'w': 0.3, 'h': 0.3} and out['movedMinimizedFractions'] is None
        assert out['badMoveSame'] and out['endedOtherSame'] and out['unknownSame'] and out['nullSame']
        assert out['ended'] is None and out['fromNothing'] is None
        assert out['effective'] == ['tab', 'window', 'window', None]
        assert out['parsed'][:3] == [None, None, None]
        assert out['parsed'][3] == {'id': 'r1', 'mode': 'window', 'fractions': None}    # bad fractions dropped alone
        assert out['parsed'][4] is None                                                  # too old
        assert out['parsed'][5] == {'id': 'r1', 'mode': 'window', 'fractions': {'x': 0.1, 'y': 0.1, 'w': 0.3, 'h': 0.3}}
        assert out['storedNull'] is None
        assert out['storedOf'] == {'id': 'r1', 'mode': 'window', 'fractions': {'x': 0.1, 'y': 0.1, 'w': 0.3, 'h': 0.3}, 't': 42}
        assert out['sizes'] == [{'w': 640, 'h': 480}, {'w': 480, 'h': 360}, {'w': 320, 'h': 200}]
        assert out['fractions'] == {'x': 0.59, 'y': 0.504, 'w': 0.4, 'h': 0.48} and out['noArea'] is None
        assert out['full'] == {'x': 0, 'y': 32, 'w': 1280, 'h': 688} and out['fullTiny'] == {'x': 0, 'y': 32, 'w': 100, 'h': 0}
        assert out['live'] == [True, True, True, True, False, False]


TERMINAL_GEOMETRY_RUNNER = """\
import {clampRect, toFractions, toPixels, cascadePosition, defaultSize, parseFloating, CASCADE_WRAP} from './terminal_windows.js';

const area = {width: 1000, height: 800};
const rect = {x: 100, y: 50, w: 500, h: 400};
process.stdout.write(JSON.stringify({
  fractions: toFractions(rect, area),
  roundTrip: toPixels(toFractions(rect, area), area),
  pushedBack: clampRect({x: 900, y: 700, w: 500, h: 400}, area),
  shrunk: clampRect({x: 0, y: 0, w: 2000, h: 2000}, area),
  tiny: clampRect({x: 50, y: 50, w: 300, h: 200}, {width: 100, height: 100}),
  cascade: [0, 1, CASCADE_WRAP, CASCADE_WRAP + 1].map((i) => cascadePosition(i, area, {w: 300, h: 200})),
  parsed: [undefined, null, 'x', {x: 'a', y: 0, w: 0.5, h: 0.5}, {x: 0, y: 0, w: 0, h: 0.5}, {x: 1.5, y: 0, w: 0.5, h: 0.5},
           {x: 0, y: 0, w: 1, h: 1}, {x: 0.25, y: 0.5, w: 0.5, h: 0.25}].map(parseFloating),
  large: defaultSize(12, area),
  small: defaultSize(12, {width: 400, height: 300}),
  noArea: toFractions(rect, {width: 0, height: 0}),
}));
"""


class TestTerminalGeometry:
    """The pure helpers of terminal_windows.js (the floating terminal windows: a window kept
    inside the panes, its geometry as fractions of them for the spectators of a presentation, the
    cascade of the new windows, the default size of a font) run by the ``js`` runtime, skipped
    without one."""

    def test_geometry(self, tmp_path, js):
        runner = js_project(tmp_path, TERMINAL_GEOMETRY_RUNNER, 'terminal_windows.js', 'i18n.js', 'ui.js')
        out = json.loads(js.run(tmp_path, runner))
        assert out['fractions'] == {'x': 0.1, 'y': 0.0625, 'w': 0.5, 'h': 0.5}
        assert out['roundTrip'] == {'x': 100, 'y': 50, 'w': 500, 'h': 400}
        assert out['pushedBack'] == {'x': 500, 'y': 400, 'w': 500, 'h': 400}
        assert out['shrunk'] == {'x': 0, 'y': 0, 'w': 1000, 'h': 800}
        assert out['tiny'] == {'x': 0, 'y': 0, 'w': 240, 'h': 140}        # the minimums, at the corner
        assert out['cascade'] == [{'x': 16, 'y': 16, 'w': 300, 'h': 200}, {'x': 44, 'y': 44, 'w': 300, 'h': 200},
                                  {'x': 16, 'y': 16, 'w': 300, 'h': 200}, {'x': 44, 'y': 44, 'w': 300, 'h': 200}]
        assert out['parsed'] == [None] * 6 + [{'x': 0, 'y': 0, 'w': 1, 'h': 1}, {'x': 0.25, 'y': 0.5, 'w': 0.5, 'h': 0.25}]
        assert out['large'] == {'w': 596, 'h': 392}                          # 80 x 24 cells of a 12 px font
        assert out['small'] == {'w': 360, 'h': 270}                          # 90 % of a small area
        assert out['noArea'] is None


TABLE_SORT_RUNNER = """\
import {compareValues, sortRows} from './table_sort.js';

const rows = JSON.parse(process.argv[2]);
const missing = (row, key) => (row[key] === null || row[key] === undefined ? -Infinity : row[key]);
const logins = (sorted) => sorted.map((row) => row.login);
process.stdout.write(JSON.stringify({
  compare: [compareValues(2, 10), compareValues('2', '10'), compareValues('etu10', 'etu9'), compareValues('10.0.1.9', '10.0.1.10'),
            compareValues('Étude', 'etude'), compareValues(null, ''), compareValues(undefined, 'a'), compareValues(-Infinity, 0),
            compareValues(Infinity, 5), compareValues(3, '3'), compareValues(NaN, -Infinity)].map(Math.sign),
  byLoginAsc: logins(sortRows(rows, {key: 'login', asc: true})),
  byLoginDesc: logins(sortRows(rows, {key: 'login', asc: false})),
  byTimeDesc: logins(sortRows(rows, {key: 'time', asc: false}, {value: missing})),
  byTimeAsc: logins(sortRows(rows, {key: 'time', asc: true}, {value: missing})),
  byNameTies: logins(sortRows(rows, {key: 'name', asc: true})),
  byNameTieKey: logins(sortRows(rows, {key: 'name', asc: true}, {tieKey: 'login'})),
  untouched: logins(rows),
}));
"""
TABLE_SORT_ROWS = [{'login': 'etu10', 'name': 'b', 'time': 5}, {'login': 'etu9', 'name': 'A', 'time': None},
                   {'login': 'Etu2', 'name': 'b', 'time': 50}, {'login': 'prof', 'name': '', 'time': 5}]


POINTER_MODEL_RUNNER = """\
import {nodePath, resolvePath, parseLocator, parseSelection, selectionCells, selectionRows, terminalSelectionLength,
        cellAt, cellFractions, fraction, rowText, MAX_PATH_DEPTH, MAX_ROW_TEXT} from './pointer_model.js';

// a fake DOM: nodes with childNodes and parentNode only
function node(...children) {
  const n = {childNodes: children, parentNode: null};
  for (const c of children) { c.parentNode = n; }
  return n;
}
const text = node();
const code = node(node());
const p = node(node(), text, code);
const h1 = node(node());
const root = node(h1, p);
const outside = node(node());
const chainRoot = node();
let deepest = chainRoot;
for (let i = 0; i < MAX_PATH_DEPTH + 2; i++) { const child = node(); child.parentNode = deepest; deepest.childNodes = [child]; deepest = child; }

const path = nodePath(root, text);
const resolved = resolvePath(root, path);
const short = resolvePath(root, [1, 7, 2]);
const empty = resolvePath(root, []);

// two terminals showing the same output: the presenter's wrote a blank line of its own first
// and has 24 rows, the spectator's (its grid is the pty's) starts on the first row
const presenter = ['', 'mock$ echo sel$((1))ect', 'sel1ect', 'mock$'];
const spectator = ['mock$ echo sel$((1))ect', 'sel1ect', 'mock$'];
const at = (lines) => (y) => (y < lines.length ? lines[y] : '');
const selected = selectionCells({start: {x: 0, y: 2}, end: {x: 7, y: 2}}, 3, at(presenter));
const repeated = ['mock$', 'x', 'mock$', 'x', 'mock$'];
const promptMiddle = selectionCells({start: {x: 0, y: 2}, end: {x: 5, y: 2}}, 4, at(repeated));
const span = selectionCells({start: {x: 3, y: 1}, end: {x: 2, y: 3}}, 4, at(['a', 'bb', 'ccc', 'dddd', 'e']));
process.stdout.write(JSON.stringify({
  path,
  roundTrip: resolved.node === text && resolved.exact,
  rootPath: nodePath(root, root),
  codeText: nodePath(root, code.childNodes[0]),
  outside: nodePath(root, outside.childNodes[0]),
  tooDeep: nodePath(chainRoot, deepest),
  short: {exact: short.exact, isP: short.node === p},
  empty: {exact: empty.exact, isRoot: empty.node === root},
  lengths: [terminalSelectionLength(3, 10, 5, 12, 80), terminalSelectionLength(3, 10, 9, 10, 80), terminalSelectionLength(0, 10, 80, 10, 80)],
  selected,
  onSpectator: selectionRows(selected, 2, 25, at(spectator)),
  lagging: selectionRows(selected, 0, 25, at(spectator.slice(0, 2))),
  notYet: selectionRows(selected, 0, 25, at(spectator.slice(0, 1))),
  ahead: selectionRows(selected, 5, 25, at([...spectator, 'more', 'mock$', 'end'])),
  farAway: selectionRows(selected, 300, 400, at(spectator)),
  promptMiddle: selectionRows(promptMiddle, 4, 5, at(repeated)),
  span,
  spanFound: selectionRows(span, 6, 8, at(['', '', 'a', 'bb', 'ccc', 'dddd', 'e', ''])),
  longText: rowText('x'.repeat(MAX_ROW_TEXT + 10)).length,
  cells: [cellAt(0.5, 0.25, 80, 24), cellAt(0.51, 0.26, 80, 24), cellAt(1, 1, 80, 24), cellAt(-0.2, 0.5, 80, 24)],
  fractions: [
    cellFractions({col: 40, fromCursor: 2, fx: 0.5, fy: 0.5}, 10, 0, 80, 24),
    cellFractions({col: 40, fromCursor: 2, fx: 0.5, fy: 0.5}, 110, 100, 80, 24),
    cellFractions({col: 100, fromCursor: 0, fx: 0.5, fy: 0}, 10, 0, 80, 24),
    cellFractions({col: 0, fromCursor: 12, fx: 0, fy: 0}, 10, 0, 80, 24),
    cellFractions({col: 0, fromCursor: -20, fx: 0, fy: 0}, 10, 0, 80, 24),
  ],
  locators: [
    parseLocator({tab: 'informations', path: [0, 1], fx: 0.5, fy: 0.25}),
    parseLocator({tab: 'informations', path: [0, 1, 0], offset: 12, len: 40, fy: 0.5}),
    parseLocator({tabbar: true, path: [2], fx: 0.1, fy: 0.9}),
    parseLocator({terminal: 'abc', col: 3, fromCursor: -2, fx: 0.3, fy: 0.8}),
    parseLocator({terminal: 'abc', part: 'window', fx: 0.3, fy: 0.8}),
  ],
  badLocators: [null, 'x', {tab: 1, path: [], fx: 0, fy: 0}, {tab: 'a', path: ['x'], fx: 0, fy: 0},
                {terminal: 'id', col: 1, fromCursor: 0, fx: 2, fy: 0}, {terminal: 'id', part: 'frame', fx: 0, fy: 0},
                {terminal: 'id', fx: 0.5, fy: 0.5}, {terminal: 'id', col: 1.5, fromCursor: 0, fx: 0, fy: 0},
                {tab: 'a', path: [0], offset: 3, fy: 0}, {tab: 'a', path: [0], fy: 0}].map(parseLocator),
  selections: [
    parseSelection({tab: 'informations', start: {path: [1, 1], offset: 2, len: 40}, end: {path: [1, 2, 0], offset: 3}}),
    parseSelection({terminal: 'abc', ...selected}),
  ],
  badSelections: [null, {tab: 'a'}, {tab: 'a', start: {path: [0], offset: 1}, end: {path: [0], offset: -1}},
                  {terminal: 'abc', start: {x: 2, fromCursor: 5, text: ''}, end: {x: 'a', fromCursor: 3, text: ''}},
                  {terminal: 'abc', start: {x: 2, fromCursor: 5}, end: {x: 4, fromCursor: 3, text: ''}},
                  {terminal: 'abc', start: {x: 2, fromCursor: 1, text: ''}, end: {x: 4, fromCursor: 3, text: ''}},
                  {terminal: 'abc', start: {x: 2, fromCursor: 1, text: 'y'.repeat(MAX_ROW_TEXT + 1)}, end: {x: 4, fromCursor: 0, text: ''}},
                 ].map(parseSelection),
  fractionsOf: [fraction(150, 100, 200), fraction(50, 100, 200), fraction(400, 100, 200), fraction(5, 0, 0), fraction(10, 0, 30)],
}));
"""


class TestPointerModel:
    """The pure helpers of pointer_model.js (the presenter's pointer and selection of a
    presentation: the paths of child indices naming a node of a pane, the cells of a terminal
    counted from its cursor and found again by the text of their rows, the shapes of the locators
    and selections), run by the ``js`` runtime on a fake DOM, skipped without one."""

    def test_model(self, tmp_path, js):
        runner = js_project(tmp_path, POINTER_MODEL_RUNNER, 'pointer_model.js')
        out = json.loads(js.run(tmp_path, runner))
        assert out['path'] == [1, 1] and out['roundTrip'] is True and out['rootPath'] == []
        assert out['codeText'] == [1, 2, 0] and out['outside'] is None and out['tooDeep'] is None
        assert out['short'] == {'exact': False, 'isP': True} and out['empty'] == {'exact': True, 'isRoot': True}
        assert out['lengths'] == [162, 6, 80]
        # the rows counted from the cursor, with their text: the same line on the spectator's
        # terminal whatever its height and the blank line the presenter's wrote first; found when
        # the spectator's output lags or runs ahead, not before it holds the row nor far away
        assert out['selected'] == {'start': {'x': 0, 'fromCursor': 1, 'text': 'sel1ect'},
                                   'end': {'x': 7, 'fromCursor': 1, 'text': 'sel1ect'}}
        found = {'startX': 0, 'startY': 1, 'endX': 7, 'endY': 1}
        assert out['onSpectator'] == found and out['lagging'] == found and out['ahead'] == found
        assert out['notYet'] is None and out['farAway'] is None
        assert out['promptMiddle'] == {'startX': 0, 'startY': 2, 'endX': 5, 'endY': 2}    # the nearest of the same lines
        assert out['span'] == {'start': {'x': 3, 'fromCursor': 3, 'text': 'bb'}, 'end': {'x': 2, 'fromCursor': 1, 'text': 'dddd'}}
        assert out['spanFound'] == {'startX': 3, 'startY': 3, 'endX': 2, 'endY': 5}
        assert out['longText'] == 256
        assert out['cells'] == [{'col': 40, 'row': 6, 'fx': 0, 'fy': 0}, {'col': 40, 'row': 6, 'fx': 0.8, 'fy': 0.24},
                                {'col': 79, 'row': 23, 'fx': 1, 'fy': 1}, {'col': 0, 'row': 12, 'fx': 0, 'fy': 0}]
        assert out['fractions'] == [{'fx': 0.5062, 'fy': 0.3542}, {'fx': 0.5062, 'fy': 0.3542}, {'fx': 1, 'fy': 0.4167},
                                    None, None]
        assert out['locators'] == [
            {'tab': 'informations', 'path': [0, 1], 'fx': 0.5, 'fy': 0.25},
            {'tab': 'informations', 'path': [0, 1, 0], 'offset': 12, 'len': 40, 'fy': 0.5},
            {'tabbar': True, 'path': [2], 'fx': 0.1, 'fy': 0.9},
            {'terminal': 'abc', 'part': 'screen', 'col': 3, 'fromCursor': -2, 'fx': 0.3, 'fy': 0.8},
            {'terminal': 'abc', 'part': 'window', 'fx': 0.3, 'fy': 0.8},
        ]
        assert out['badLocators'] == [None] * 10
        assert out['selections'] == [
            {'tab': 'informations', 'start': {'path': [1, 1], 'offset': 2, 'len': 40}, 'end': {'path': [1, 2, 0], 'offset': 3}},
            {'terminal': 'abc', **out['selected']},
        ]
        assert out['badSelections'] == [None] * 7
        assert out['fractionsOf'] == [0.25, 0, 1, 0, 0.3333]
        assert not re.search(r'\b(document|window)\.', (JS / 'pointer_model.js').read_text(encoding='utf-8'))


class TestTableSort:
    """table_sort.js (the headers sorting the tables of the History page) run by the ``js``
    runtime, skipped without one: numbers numerically, texts with the collation of the site
    (accents and case ignored, digit runs as numbers), the ties by a key or in the arrival order."""

    def test_compare_and_sort(self, tmp_path, js):
        runner = js_project(tmp_path, TABLE_SORT_RUNNER, 'table_sort.js')
        out = json.loads(js.run(tmp_path, runner, json.dumps(TABLE_SORT_ROWS)))
        assert out['compare'] == [-1, -1, 1, -1, 0, 0, -1, -1, 1, 0, 0]
        assert out['byLoginAsc'] == ['Etu2', 'etu9', 'etu10', 'prof']
        assert out['byLoginDesc'] == ['prof', 'etu10', 'etu9', 'Etu2']
        assert out['byTimeDesc'] == ['Etu2', 'etu10', 'prof', 'etu9']       # the ties in the arrival order
        assert out['byTimeAsc'] == ['etu9', 'etu10', 'prof', 'Etu2']
        assert out['byNameTies'] == ['prof', 'etu9', 'etu10', 'Etu2']
        assert out['byNameTieKey'] == ['prof', 'etu9', 'Etu2', 'etu10']
        assert out['untouched'] == ['etu10', 'etu9', 'Etu2', 'prof']        # a sorted copy


class TestJavaScript:
    def test_table_sort_shared_by_the_history_views(self):
        """The two list tables of the History page and the users / labs tables of its statistics
        sort their rows through table_sort.js (one notion of a sortable header), a pure module
        (runs under node); the default orders are the server's."""
        for name in ('history.js', 'history_stats.js'):
            text = (JS / name).read_text(encoding='utf-8')
            assert "from './table_sort.js'" in text, name
            assert 'function sortRows' not in text and 'function markSort' not in text and 'function setupSort' not in text, name
        history = (JS / 'history.js').read_text(encoding='utf-8')
        assert "events: {key: 'ts', asc: false}" in history and "sessions: {key: 'end', asc: false}" in history
        assert 'isOpen(session) ? Infinity' in history
        assert not re.search(r'\bdocument\.', (JS / 'table_sort.js').read_text(encoding='utf-8'))   # pure: runs under node

    def test_exam_state_shared_by_the_pages(self):
        """One notion of the exam a student is in: exam.js fetches GET /api/exam (on the pushes
        of the presence socket base.js hands it, and as a fallback poll), paints the body and
        dispatches `sre-exam`; the Projects and project pages read that state, never /api/exam
        themselves; the top bars take --exam-bg through the body class; the Logout dialog
        leaves the exam projects alone."""
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        assert '--exam-bg:' in css and re.search(r'body\.exam-bound \.topbar[^{]*\{[^}]*var\(--exam-bg\)', css)
        assert '#exam-ended' in css and 'z-index: 1100' in css.split('#exam-ended')[1].split('}')[0]
        exam = (JS / 'exam.js').read_text(encoding='utf-8')
        assert "api.get('/api/exam')" in exam and "'sre-exam-push'" in exam and "new CustomEvent('sre-exam'" in exam
        assert "'exam-bound'" in exam and '/dismiss' in exam and 'i18n.init()' in exam
        base = (JS / 'base.js').read_text(encoding='utf-8')
        assert "message.t === 'exam'" in base and "'sre-exam-push'" in base and 'setupExam()' in base
        for name in ('projects.js', 'project.js'):
            text = (JS / name).read_text(encoding='utf-8')
            assert "from './exam.js'" in text and "'sre-exam'" in text and "'/api/exam'" not in text, name
        projects = (JS / 'projects.js').read_text(encoding='utf-8')
        assert 'prestart_at' in projects and 'flavorDialog(' in projects and 'http_status === 409' in projects
        assert 'closeButton.hidden = true' in (JS / 'project.js').read_text(encoding='utf-8')
        logout = (JS / 'logout.js').read_text(encoding='utf-8')
        assert 'project.exam' in logout
        # the Open page and the members dialog share the dialogs of creation.js / login_picker.js
        assert "from './login_picker.js'" in (JS / 'group_members.js').read_text(encoding='utf-8')
        assert "from './login_picker.js'" in (JS / 'exams_form.js').read_text(encoding='utf-8')
        assert 'flavorDialog(' in (JS / 'open.js').read_text(encoding='utf-8')
        assert "from './form.js'" not in (JS / 'open.js').read_text(encoding='utf-8')

    def test_group_matching_shared_by_the_pages(self):
        """The pages match a row against a group through groups_model.js (one notion of a group
        key), never by comparing the department string themselves; the audience dialog of the
        presentations and of the web conferences is one module."""
        for name in ('watch.js', 'watch_summary.js', 'audience_dialog.js', 'groups.js', 'group_members.js'):
            assert "from './groups_model.js'" in (JS / name).read_text(encoding='utf-8'), name
        watch = (JS / 'watch.js').read_text(encoding='utf-8')
        assert 'rowMatchesGroup(row, state.group)' in watch and "el('optgroup'" in watch
        assert "table.dataset.groupSources === 'true'" in watch and 'row.group === state.group' not in watch
        # the group chosen last is remembered by the browser (tests/test_web_watch_browser.py drives it)
        assert "'sreweb.watch'" in watch and 'window.localStorage' in watch and 'storedGroup()' in watch
        summary = (JS / 'watch_summary.js').read_text(encoding='utf-8')
        assert 'rowMatchesGroup(r, c.group)' in summary and 'r.group === c.group' not in summary
        audience = (JS / 'audience_dialog.js').read_text(encoding='utf-8')
        assert 'rowGroupKeys(row)' in audience and "api.get('/api/groups')" in audience and 'normalizeKey' in audience
        assert 'groupSet.has(row.group)' not in audience and "_('in a conference')" in audience
        present = (JS / 'present.js').read_text(encoding='utf-8')
        assert "from './audience_dialog.js'" in present and "'/api/presence'" not in present and 'rowGroupKeys' not in present
        assert 'groupSources: groups' in present
        webconf_dialog = (JS / 'webconf_dialog.js').read_text(encoding='utf-8')
        assert "from './audience_dialog.js'" in webconf_dialog
        # an empty audience may be chosen for a conference room, never for a presentation
        assert 'ok.disabled = !allowEmpty && ' in audience and 'allowEmpty = false' in audience
        assert 'allowEmpty: true' in webconf_dialog and 'allowEmpty' not in present
        project = (JS / 'project.js').read_text(encoding='utf-8')
        assert "body.dataset.groupSources === 'true'" in project and 'groups: groupSourcesEnabled' in project
        assert not re.search(r'\bdocument\.', (JS / 'groups_model.js').read_text(encoding='utf-8'))   # pure: runs under node

    def test_webconf_wiring(self):
        """The web conference (webconf.js): one iframe fixed over a slot, never moved in the DOM,
        hidden with visibility (alive) while its slot is not shown; the push handed over by
        base.js on every page of a logged-in user outside the presentation iframe; the Webconf tab
        of the project page and the generalised chrome of the terminal windows; the pure model."""
        base = (JS / 'base.js').read_text(encoding='utf-8')
        assert "message.t === 'webconf'" in base and 'webconf.onPush(message)' in base
        guarded = base[base.index('if (body.dataset.login && !framed)'):]
        assert 'webconf.setup()' in guarded and 'setupWebconfDialog()' in guarded
        webconf = (JS / 'webconf.js').read_text(encoding='utf-8')
        assert "from './webconf_model.js'" in webconf and "from './terminal_windows.js'" in webconf
        assert "'camera *; microphone *; display-capture *; fullscreen; autoplay'" in webconf
        assert "id: 'webconf-frame'" in webconf and "visibility = 'hidden'" in webconf
        assert "display = 'none'" not in webconf and 'display: none' not in webconf
        assert "window.open(state.joinUrl, 'sre-webconf-' + state.id, POPUP_FEATURES)" in webconf
        assert "ev.data.t !== 'webconf-left'" in webconf and 'ev.origin !== window.location.origin' in webconf
        assert "new BroadcastChannel(CHANNEL)" in webconf and "'pagehide'" in webconf and "'pageshow'" in webconf
        assert "'sreweb.webconf'" not in webconf                      # the storage key lives in the model
        model = (JS / 'webconf_model.js').read_text(encoding='utf-8')
        assert "STORAGE_KEY = 'sreweb.webconf'" in model
        assert not re.search(r'\b(document|window)\.', model)       # pure: runs under node
        project = (JS / 'project.js').read_text(encoding='utf-8')
        assert "case 'webconf': return spectator ? null : createWebconfTab(ctx);" in project
        shut_down = project[project.index('function shutDown()'):project.index('function projectClosed()')]
        assert 'setWebconfTabHost(null)' in shut_down
        select_tab = project[project.index('function selectTab('):project.index('function renderTabBar(')]
        assert '!isListed(id)' in select_tab
        for name in ('function focusView()', 'function getView()'):
            body = project[project.index(name):]
            assert 'tab: sharedTab()' in body[:body.index('\n}\n')], name
        assert "currentTab === 'webconf' ? null : currentTab" in project
        tab = (JS / 'tabs' / 'webconf.js').read_text(encoding='utf-8')
        assert 'setTabHost({' in tab and "from '../webconf.js'" in tab
        windows = (JS / 'terminal_windows.js').read_text(encoding='utf-8')
        assert 'buttons = null' in windows and 'onMove = null' in windows and 'onMove(rect)' in windows
        left = (JS / 'webconf_left.js').read_text(encoding='utf-8')
        assert "t: 'webconf-left'" in left and 'window.location.origin' in left
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        assert re.search(r'#webconf-frame\s*\{[^{}]*position: fixed', css)
        assert re.search(r'#webconf-frame\.dragging\s*\{[^{}]*pointer-events: none', css)

    def test_group_names_are_url_encoded(self):
        """Every group name or login put in a path of the groups API goes through encodeURIComponent."""
        for name in ('groups.js', 'group_members.js'):
            text = (JS / name).read_text(encoding='utf-8')
            for match in re.finditer(r'/api/groups/[^`]*?\$\{([^}]*)\}', text):
                assert match.group(1).startswith('encodeURIComponent('), f"{name}: {match.group(0)}"

    def test_every_module_parses(self):
        esprima = pytest.importorskip('esprima')
        modules = js_modules()
        assert len(modules) >= 15
        for module in modules:
            try:
                esprima.parseModule(module.read_text(encoding='utf-8'))
            except esprima.Error as e:   # pragma: no cover - the message names the file
                pytest.fail(f"{module.relative_to(ROOT)}: {e}")

    def test_no_console_log_left(self):
        for module in js_modules():
            assert 'console.log' not in module.read_text(encoding='utf-8'), module.name

    def test_i18n_calls_are_made_at_runtime(self):
        """_() reads the catalog fetched by init(): no translated string at the top level of a
        module (they would be looked up before the catalog is loaded)."""
        for module in js_modules():
            depth = 0
            for line in module.read_text(encoding='utf-8').splitlines():
                stripped = line.split('//')[0]
                if depth == 0 and TRANSLATED_STRING.search(stripped):
                    pytest.fail(f"{module.name}: _() at the module top level: {line.strip()}")
                depth += stripped.count('{') + stripped.count('(') - stripped.count('}') - stripped.count(')')

    def test_presentation_colour_keyed_on_the_body(self):
        """The top bars take --presentation-bg while a presentation is on: the presenter's page
        through the body class present.js sets and removes, the presented page through its
        data-presentation attribute (project.html)."""
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        assert '--presentation-bg:' in css
        rule = re.search(r'([^{}]*)\{[^{}]*var\(--presentation-bg\)', css)
        assert rule, "no rule uses --presentation-bg"
        selectors = [s.strip() for s in rule.group(1).split(',')]
        for selector in ('body.presenting .topbar', 'body.presenting .project-bar',
                         'body.presenting .presentation-bar', 'body[data-presentation] .project-bar'):
            assert selector in selectors, selector
        present = (JS / 'present.js').read_text(encoding='utf-8')
        assert "classList.add('presenting')" in present and "classList.remove('presenting')" in present

    def test_helper_colour_keyed_on_the_body(self):
        """An instructor's page on a student's project takes --helper-bg on its site bar and
        project bar (body.helping, set by project.js for an instructor who is neither the owner
        nor a spectator); the rule precedes the presentation one, so the presentation colour
        wins while that project is presented."""
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        assert '--helper-bg:' in css
        rule = re.search(r'([^{}]*)\{[^{}]*var\(--helper-bg\)', css)
        assert rule, "no rule uses --helper-bg"
        selectors = [s.strip() for s in rule.group(1).split(',')]
        assert 'body.helping .topbar' in selectors and 'body.helping .project-bar' in selectors
        assert css.index('var(--helper-bg)') < css.index('var(--presentation-bg)')
        project = (JS / 'project.js').read_text(encoding='utf-8')
        helper = next((l for l in project.splitlines() if l.startswith('const helper =')), None)
        assert helper, "project.js never defines the helper"
        for token in ('isInstructor', '!isOwner', '!spectator'):
            assert token in helper, token
        line = next((l for l in project.splitlines() if "classList.add('helping')" in l), None)
        assert line, "project.js never sets body.helping"
        assert 'if (helper)' in line

    def test_last_archived_evaluation_keyed_on_the_helper(self):
        """The last archived evaluation (numeric, exo scope) is loaded by the Evaluation tab of a
        helper (an instructor on somebody else's project, ctx.helper of project.js), on show and
        on the `evaluated` event; never by the owner's page, instructor or not, which keeps the
        rows of its own self-evaluation (the letters of a lab hiding the marks: an
        owner-instructor saw numbers until 2026-10-30), nor by a spectator's page, which shows
        the table the presenter's page publishes (present.js publishEvaluation → PUT
        .../evaluation → the `evaluation` message of the presentation socket → setTable; the
        spectators of an owner-instructor saw the numbers of the archive until 2026-10-30)."""
        project = (JS / 'project.js').read_text(encoding='utf-8')
        assert re.search(r'^const helper = isInstructor && !isOwner && !spectator;$', project, re.M)
        assert re.search(r'^  helper,$', project, re.M), "ctx.helper is not exposed to the tabs"
        evaluated = project[project.index("case 'evaluated':"):]
        evaluated = evaluated[:evaluated.index('break;')]
        assert 'tabs.evaluation.reload()' in evaluated and 'if (tabs.evaluation && ctx.helper)' in evaluated
        assert 'isInstructor' not in evaluated and 'spectator)' not in evaluated
        apply_view = project[project.index('function applyView('):]
        apply_view = apply_view[:apply_view.index('\n}\n')]
        assert 'evaluated' not in apply_view and 'view.answers' in apply_view
        assert "message.t === 'evaluation'" in project and 'applyEvaluation(message.evaluation)' in project
        assert 'getEvaluation: () =>' in project and 'tabs.evaluation.getTable()' in project
        assert 'presenter.publishEvaluation()' in project
        evaluation = (JS / 'tabs' / 'evaluation.js').read_text(encoding='utf-8')
        show = evaluation[evaluation.index('show() {'):]
        show = show[:show.index('hide() {')]
        assert 'loadLast()' in show and 'ctx.helper && !lastLoaded' in show and 'spectator' not in show
        assert 'isInstructor' not in evaluation and 'getTable()' in evaluation and 'setTable(' in evaluation
        present = (JS / 'present.js').read_text(encoding='utf-8')
        assert 'function publishEvaluation()' in present and "'/evaluation'" in present
        assert 'const counters = {answers: 0};' in present
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        assert 'const helper = Boolean(ctx.helper);' in terminals

    def test_shared_terminals_only_on_devices_open_to_the_student(self):
        """A terminal an instructor opens on a device the student may not open themself (a closed
        machine or switch, a hidden machine) is made private by the agent whatever the page asks
        (security review finding 5): the page greys the shared kind of the selects for such a
        device and retitles a terminal the ready frame reports private."""
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        assert 'function openToStudent(device)' in terminals
        assert 'return Boolean(!device.hidden && (device.allow_connection || debug));' in terminals
        assert "option.disabled = !canOpen(device) || (prefix === 'shared:' && !openToStudent(device));" in terminals
        assert "option.title = _('Closed to the student: private terminal only');" in terminals
        assert 'if (info.private && !entry.private) {' in terminals
        assert "setTitle(entry, format(_('{title} (private)'), {title: entry.title}));" in terminals
        app = (ROOT / 'src' / 'sreweb' / 'agent' / 'app.py').read_text(encoding='utf-8')
        assert 'if privileged and not access.device_open_to_students(project.info, device):' in app
        assert "'private': session.private" in app

    def test_display_clipboard_received_by_the_owner_only(self):
        """The X selection of a project's desktop is set by any X client of its containers: the
        Display tab writes it into the textarea and the browser's clipboard on the owner's page
        only (security review finding 4); a helping instructor can still send text."""
        display = (JS / 'tabs' / 'display.js').read_text(encoding='utf-8')
        guard = display.index('if (!spectator && ctx.isOwner) {')
        listener = display.index("session.addEventListener('clipboard'")
        write = display.index('navigator.clipboard.writeText(')
        assert guard < listener < write
        assert display.count("addEventListener('clipboard'") == 1 and display.count('writeText(') == 1
        assert "ctx.isOwner ? _('Text to paste into the X desktop, or received from it') : _('Text to paste into the X desktop')" in display
        assert "rfb.clipboardPasteFrom(clipboard.value)" in display      # sending stays for everybody but a spectator

    def test_terminal_links_open_on_the_owners_page_only(self):
        """The OSC 8 hyperlinks of a terminal's output (the student's containers print them)
        open, http(s) only and after a confirm naming the target, on the owner's page only; a
        helping instructor's or a spectator's page keeps them inert (security review, first Low
        finding): xterm.js gets a linkHandler instead of its default confirm + window.open."""
        terminal = (JS / 'terminal.js').read_text(encoding='utf-8')
        assert 'linkHandler: this.linkHandler(links),' in terminal
        handler = terminal[terminal.index('  linkHandler(links) {'):terminal.index('  constructor(')]
        assert 'allowNonHttpProtocols: false,' in handler
        assert "if (!links || !/^https?:\\/\\//i.test(uri)) {" in handler
        assert "window.confirm(_('Open this link in a new tab?') + '\\n\\n' + uri)" in handler
        assert "window.open(uri, '_blank', 'noopener,noreferrer');" in handler
        assert 'container.title = uri;' in handler and "container.title = '';" in handler
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        assert 'links: Boolean(ctx.isOwner) && !spectator,' in terminals

    def test_focus_colour_keyed_on_the_body(self):
        """While an instructor focuses a student on the project, both pages take --focus-bg on
        their top bars (body.focusing on the instructor's page, body.focused on the student's,
        both set by focus.js), a colour of its own, different from the helper colour the
        instructor's page has otherwise; its rule comes after the helper rule (same specificity:
        it wins while the mode is on) and before the presentation rule (the lavender still
        wins while the project is presented)."""
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        tokens = dict(re.findall(r'(--[a-z-]+-bg):\s*(#[0-9a-fA-F]+)', css))
        assert '--focus-bg' in tokens and tokens['--focus-bg'].lower() != tokens['--helper-bg'].lower()
        rule = re.search(r'([^{}]*)\{[^{}]*var\(--focus-bg\)', css)
        assert rule, "no rule uses --focus-bg"
        selectors = [s.strip() for s in rule.group(1).split(',')]
        for selector in ('body.focusing .topbar', 'body.focusing .project-bar',
                         'body.focused .topbar', 'body.focused .project-bar'):
            assert selector in selectors, selector
        assert css.index('var(--helper-bg)') < css.index('var(--focus-bg)') < css.index('var(--presentation-bg)')
        focus = (JS / 'focus.js').read_text(encoding='utf-8')
        for cls in ('focusing', 'focused'):
            assert f"classList.add('{cls}')" in focus and f"classList.remove('{cls}')" in focus, cls

    def test_pool_state_colours_tell_off_from_disabled(self):
        """The State cell of the Pool page: a host whose agent does not answer (off) and a host
        taken out of the pool by hand (disabled) have each a background of their own, so that
        the two are told apart at a glance (both were the same grey): a rule and a colour token
        each, the values different from each other and from the green / amber of the other
        states."""
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        tokens = dict(re.findall(r'(--[a-z-]+-bg):\s*(#[0-9a-fA-F]+)', css))
        rules = {}
        for cls in ('off', 'disabled'):
            rule = re.search(r'([^{}]*\.state\.%s\b[^{}]*)\{([^{}]*)\}' % cls, css)
            assert rule, f"no rule for td.state.{cls}"
            token = re.search(r'background:\s*var\((--[a-z-]+-bg)\)', rule.group(2))
            assert token, f"td.state.{cls} has no background token"
            assert token.group(1) in tokens, token.group(1)
            rules[cls] = (rule.group(1).strip(), token.group(1))
        assert rules['off'][0] != rules['disabled'][0], "one selector list for both states"
        colours = {cls: tokens[token].lower() for cls, (_, token) in rules.items()}
        assert colours['off'] != colours['disabled']
        for other in ('--ok-bg', '--debug-bg'):
            assert colours['off'] != tokens[other].lower() and colours['disabled'] != tokens[other].lower(), other

    def test_pool_button_tones(self):
        """The buttons of a host (pool.js) and the bulk ones of the bar (pool.html) carry a tone
        class: Enable the green of the Connect buttons (ok, --ok-bg), Wake a lighter green
        (ok-light, --ok-light-bg, a tint of its own), Disable and Power off the red text of danger;
        the green rules come after button:hover so the colour stays under the mouse."""
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        tokens = dict(re.findall(r'(--[a-z-]+-bg):\s*(#[0-9a-fA-F]+)', css))
        assert tokens['--ok-light-bg'].lower() != tokens['--ok-bg'].lower()
        for cls, token in (('ok', '--ok-bg'), ('ok-light', '--ok-light-bg')):
            rule = re.search(r'([^{}]*)\{[^{}]*var\(%s\)[^{}]*\}' % token, css[css.index(f'button.{cls} '):])
            assert rule and f'button.{cls}' in [s.strip() for s in rule.group(1).split(',')], f"no rule for button.{cls}"
            assert css.index('button:hover') < css.index(f'button.{cls} ')
        pool = (JS / 'pool.js').read_text(encoding='utf-8')
        assert "actionButton(row, 'enable', _('Enable'), {tone: 'ok'})" in pool
        assert "actionButton(row, 'wake', _('Wake'), {tone: 'ok-light'," in pool
        assert "actionButton(row, 'disable', _('Disable'), {tone: 'danger'})" in pool
        html = render('pool.html', instructor=True)
        for action, cls in (('enable', 'ok'), ('wake', 'ok-light'), ('disable', 'danger'), ('poweroff', 'danger')):
            assert re.search(r'<button[^>]*data-action="%s"[^>]*class="%s"' % (action, cls), html), action

    def test_focus_never_names_a_private_terminal(self):
        """The terminal sub-tab a focus shares is taken from focusTarget() of the terminals tab,
        which leaves a private terminal out (the student must not see nor join an instructor's
        private terminal), and focusSession() joins no private session."""
        project = (JS / 'project.js').read_text(encoding='utf-8')
        line = next((l for l in project.splitlines() if l.strip().startswith('terminal:')), None)
        assert line and 'focusTarget()' in line and 'getView' not in line, line
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        assert 'function focusTarget()' in terminals and 'function isPrivate(entry)' in terminals
        target = terminals[terminals.index('function focusTarget()'):terminals.index('function focusSession(')]
        assert '!isPrivate(entry)' in target
        session = terminals[terminals.index('function focusSession('):terminals.index('function autoJoin(')]
        assert '!r.private' in session and session.index('!r.private') < session.index('join(r)')
        # the live list of a student never offers a private session
        live = terminals[terminals.index('function renderLive()'):terminals.index('function openNew(')]
        assert '!r.private || ctx.isInstructor' in live

    def test_answers_editable_by_an_instructor(self):
        """An instructor on a student's project writes the answers like the student (the agent
        keeps the student's metadata): no script carries a read-only flag of the answers any
        more; a spectator of a presentation still reads them (ctx.answersReadonly())."""
        for path in sorted(JS.rglob('*.js')):
            if 'vendor' not in path.parts:
                assert 'answers_readonly' not in path.read_text(encoding='utf-8'), path
        project = (JS / 'project.js').read_text(encoding='utf-8')
        readonly = project[project.index('answersReadonly() {'):]
        assert readonly[:readonly.index('}')].strip().endswith('return spectator;')
        questions = (JS / 'tabs' / 'questions.js').read_text(encoding='utf-8')
        changed = questions[questions.index('function changed('):questions.index('async function flush(')]
        assert 'ctx.answersReadonly()' in changed
        assert 'control.disabled = true' in questions[questions.index('function setReadonly('):]

    def test_presentation_follows_the_scroll(self):
        """The spectators follow the position inside the tab shown: the view carries `scroll`
        (what the current tab's getScroll() reports: the anchor of a scrolling pane, scroll.js,
        or the viewBox of a schema), applied by the same tab on a spectator's page once the
        pane is shown (after selectTab); the presenter's page publishes on every scroll event
        of a pane (one capturing listener: scroll events do not bubble) and on every change of
        the schema's viewBox, through ctx.onScroll, never through ctx.onViewChange (the focus
        does not share the scroll); present.js follows a scroll in progress (a maximum wait)
        and sends nothing when the view is the one last sent."""
        project = (JS / 'project.js').read_text(encoding='utf-8')
        get_view = project[project.index('function getView()'):project.index('async function load()')]
        assert 'scroll: current && current.getScroll ? current.getScroll() : null' in get_view
        apply_view = project[project.index('function applyView('):project.index('function onEvent(')]
        assert 'selectTab(view.tab);' in apply_view
        assert apply_view.index('selectTab(view.tab);') < apply_view.index('current.setScroll(view.scroll || null)')
        hooks = project[project.index('if (!spectator) {'):project.index('// -- tabs')]
        assert 'ctx.onScroll = () => {' in hooks and 'presenter.schedule()' in hooks
        assert "panes.addEventListener('scroll', () => ctx.onScroll(), {capture: true, passive: true})" in hooks
        on_view_change = hooks[hooks.index('ctx.onViewChange = () => {'):hooks.index('ctx.onEvaluated')]
        assert 'focus.schedule()' in on_view_change and 'onScroll' not in on_view_change
        present = (JS / 'present.js').read_text(encoding='utf-8')
        assert 'const PUBLISH_MAX_DELAY = ' in present
        publish = present[present.index('async function publish()'):present.index('// -- presenting')]
        assert 'if (key === lastKey) {' in publish and publish.index('await inFlight;') < publish.index('lastKey = key;')
        focus = (JS / 'focus.js').read_text(encoding='utf-8')
        keys = next(l for l in focus.splitlines() if l.startswith('const VIEW_KEYS = '))
        assert 'scroll' not in keys
        # every tab with a position of its own
        for name in ('informations', 'machines', 'networks', 'states', 'evaluation', 'log', 'questions', 'schema'):
            tab = (JS / 'tabs' / f'{name}.js').read_text(encoding='utf-8')
            assert "from '../scroll.js'" in tab or 'function getScroll()' in tab, name
            assert 'paneScroll(' in tab or ('getScroll' in tab and 'setScroll' in tab), name
        for name in ('terminals', 'display'):
            assert 'getScroll' not in (JS / 'tabs' / f'{name}.js').read_text(encoding='utf-8'), name
        schema = (JS / 'tabs' / 'schema.js').read_text(encoding='utf-8')
        assert 'new SvgPanZoom(view, {onChange: () => {' in schema and 'ctx.onScroll()' in schema
        panzoom = (JS / 'svgpanzoom.js').read_text(encoding='utf-8')
        assert 'setView(box) {' in panzoom
        apply = panzoom[panzoom.index('apply() {'):panzoom.index('setView(box) {')]
        assert 'this.onChange()' in apply

    def test_presentation_shows_the_pointer_and_the_selection(self):
        """The spectators see the presenter's mouse pointer and selection (pointer.js): the pointer
        as text frames of the presenter's presentation socket ({t: 'pointer'}, parsed by the portal
        for the presenter only, applied by setPointer), the selection as the `selection` key of the
        view (applied after the terminals it may name are joined); the pure helpers (the paths of
        child indices, the rows of a terminal counted from the bottom) live in pointer_model.js,
        DOM-free; the terminals tab gives the terminal under the mouse and the one of a session and
        tells the hook of every change of a terminal's selection; a read-only terminal draws the
        applied selection in the presentation colour; the pointer element lets the mouse through
        and sits over the terminal windows, under the exam overlay and the toasts."""
        project = (JS / 'project.js').read_text(encoding='utf-8')
        assert "message.t === 'pointer'" in project and 'pointerView.setPointer(message.pointer)' in project
        get_view = project[project.index('function getView()'):project.index('async function load()')]
        assert 'selection: pointerTracker ? pointerTracker.getSelection() : null' in get_view
        apply_view = project[project.index('function applyView('):project.index('function onEvent(')]
        assert 'pointerView.setSelection(view.selection || null)' in apply_view
        assert apply_view.index('terminals.setView(') < apply_view.index('pointerView.setSelection(')
        hooks = project[project.index('if (!spectator) {'):project.index('// -- tabs')]
        assert 'ctx.onSelectionChange = (remoteId, term) => {' in hooks
        assert "from './pointer.js'" in project and 'pointerView.destroy()' in project
        present = (JS / 'present.js').read_text(encoding='utf-8')
        for token in ('tracker.start(', 'tracker.stop()', 'tracker.resend()'):
            assert token in present, token
        events = (JS / 'events.js').read_text(encoding='utf-8')
        assert '  send(obj) {' in events and 'readyState !== WebSocket.OPEN' in events
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        for token in ('function terminalAt(element)', 'function terminalByRemote(remoteId)', 'if (ctx.onSelectionChange) {',
                      'session.term.onSelectionChange('):
            assert token in terminals, token
        assert 'getScroll' not in terminals
        terminal = (JS / 'terminal.js').read_text(encoding='utf-8')
        assert 'selectionInactiveBackground' in terminal and 'themeFor(scheme, this.readonly)' in terminal
        # the size the box took while the socket was connecting is sent once it is open: the pty,
        # and so a spectator's grid, has the size of the presenter's terminal
        opened = terminal[terminal.index("socket.addEventListener('open', () => {"):terminal.index("socket.addEventListener('message'")]
        assert 'this.size.cols !== query.cols || this.size.rows !== query.rows' in opened and "t: 'resize'" in opened
        pointer = (JS / 'pointer.js').read_text(encoding='utf-8')
        assert "from './pointer_model.js'" in pointer
        for token in ('export function createPointerTracker(', 'export function createPointerView(', "closest('.xterm')",
                      'CSS.highlights', 'caretPositionFromPoint', 'caretRangeFromPoint', 'onWriteParsed'):
            assert token in pointer, token
        assert not re.search(r'\b(document|window)\.', (JS / 'pointer_model.js').read_text(encoding='utf-8'))
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        rule = re.search(r'^#presenter-pointer \{([^}]*)\}', css, re.M)
        assert rule and 'position: fixed' in rule.group(1) and 'pointer-events: none' in rule.group(1)
        z = int(re.search(r'z-index: (\d+)', rule.group(1)).group(1))
        assert 10 < z < 1100
        assert '::highlight(presenter-selection)' in css
        routes = (ROOT / 'src' / 'sreweb' / 'portal' / 'routes.py').read_text(encoding='utf-8')
        assert routes.index('if presenter and msg.type == WSMsgType.TEXT:') < routes.index("frame.get('t') == 'pointer'")

    def test_focus_switch_opens_no_terminal(self):
        """The terminals tab shown for the first time opens a terminal on the first open device
        (as the Qt GUI), unless a focus brought the page there (autoOpen false): the instructor
        opening a terminal (a private one, say) must not make the student's page open one of
        its own, which looked like the private terminal shown to the student."""
        project = (JS / 'project.js').read_text(encoding='utf-8')
        apply_view = project[project.index('function applyFocusView('):project.index('function getView()')]
        assert 'selectTab(view.tab, {autoOpen: false})' in apply_view
        assert 'tabs[id].show(options)' in project
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        show = terminals[terminals.index('show({autoOpen = true} = {})'):terminals.index('hide() {}')]
        assert '} else if (autoOpen) {' in show and 'openNew(first.name)' in show
        assert show.index('autoJoin()') < show.index('else if (autoOpen)')     # the helper still joins

    def test_empty_projects_page_shows_the_logo(self):
        """Without a running project the Projects page shows the SRE logo in large, as the Qt GUI
        does when no project is open (its _LogoWidget paints graphics/sysreseval.svg scaled to the
        window, aspect ratio kept, centred): the same file copied under web/static/img/, an
        element projects.js shows instead of the empty list on every poll, sized by CSS to the
        space left under the toolbar."""
        logo = STATIC / 'img' / 'sysreseval.svg'
        assert logo.read_bytes() == (ROOT / 'graphics' / 'sysreseval.svg').read_bytes()
        projects = (JS / 'projects.js').read_text(encoding='utf-8')
        assert "document.getElementById('no-project')" in projects
        assert 'logo.hidden = !empty' in projects and 'list.hidden = empty' in projects
        assert 'No running project.' not in projects
        error_path = projects[projects.index('} catch (e) {'):projects.index("class: 'error'")]
        assert 'logo.hidden = true' in error_path and 'list.hidden = false' in error_path
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        box = re.search(r'\.empty-logo\s*\{([^{}]*)\}', css)
        assert box and 'flex: 1' in box.group(1) and 'align-items: center' in box.group(1) \
            and 'justify-content: center' in box.group(1)
        img = re.search(r'\.empty-logo img\s*\{([^{}]*)\}', css)
        assert img and 'object-fit: contain' in img.group(1)

    def test_projects_cards_say_the_mode(self):
        """An instructor's cards of the Projects page say the mode of each project (Standard /
        Instructor mode / Debug mode: the words of the Project mode radios of the Open page, from
        the `debug_project` / `instructor_mode` flags of the rows of GET /api/projects), the two
        non-standard modes also as a translated, coloured suffix of the title; a student's
        projects are all standard, their cards have no Mode line. The suffix was an English-only
        CSS ::after before (2026-11-09)."""
        projects = (JS / 'projects.js').read_text(encoding='utf-8')
        assert "const isInstructor = document.body.dataset.instructor === 'true';" in projects
        assert 'function modeOf(project)' in projects and 'if (project.debug_project)' in projects
        for text in ("_('Mode: ')", "_('Standard')", "_('Instructor mode')", "_('Debug mode')",
                     "_('debug')", "_('instructor')"):
            assert text in projects, text
        assert 'if (isInstructor) {' in projects and "{class: 'mode ' + mode}" in projects
        open_html = (TEMPLATES / 'open.html').read_text(encoding='utf-8')
        for word in ('Standard', 'Instructor mode', 'Debug mode'):   # the same words as the radios
            assert f'{{{{ _("{word}") }}}}' in open_html, word
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        assert '(debug)' not in css and '--instructor-color:' in css
        assert '.card h2 .mode { font-weight: normal; }' in css
        assert '.card .mode.debug { color: var(--closed-color); }' in css
        assert '.card .mode.instructor { color: var(--instructor-color); }' in css

    def test_floating_terminal_windows(self):
        """A terminal floats over the page in a window (terminal_windows.js: the chrome, the drag
        by the title bar, the geometry as fractions of #panes), the Connect buttons of the
        Machines / Networks tabs open one without leaving their tab, the terminals tab owns every
        session, docked or in a window (the ⧉ of a sub-tab and the dock button of a window move the
        same xterm, told by moved()), the presenter's view carries the geometry of the windows for
        the spectators' read-only ones, a focus shares the terminal last gone to; the layer sits
        under the toasts and the overlays and lets the clicks between the windows through."""
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        assert "from '../terminal_windows.js'" in terminals and 'overlay: windows.element' in terminals
        for name in ('undock', 'dock'):
            body = terminals[terminals.index(f'function {name}('):]
            assert 'entry.session.moved()' in body[:body.index('\n  }\n')], name
        get_view = terminals[terminals.index('function getView()'):terminals.index('function setView(')]
        assert 'floating' in get_view and 'lastFocused' in get_view
        set_view = terminals[terminals.index('function setView('):terminals.index('function focusTarget()')]
        assert 'parseFloating(o.floating)' in set_view and 'setFractions(' in set_view
        target = terminals[terminals.index('function focusTarget()'):terminals.index('function focusSession(')]
        assert 'lastFocused' in target
        project = (JS / 'project.js').read_text(encoding='utf-8')
        start = project.index('openTerminal(device) {')
        open_terminal = project[start:project.index('selectTab,', start)]
        assert 'openWindow(' in open_terminal and 'selectTab' not in open_terminal
        assert 'panes.append(created.overlay)' in project
        for name in ('machines', 'networks'):
            assert 'ctx.openTerminal(' in (JS / 'tabs' / f'{name}.js').read_text(encoding='utf-8'), name
        windows = (JS / 'terminal_windows.js').read_text(encoding='utf-8')
        assert 'setPointerCapture(' in windows and 'clampRect(' in windows and 'readonly' in windows
        css = (STATIC / 'css' / 'sre.css').read_text(encoding='utf-8')
        layer = re.search(r'\.terminal-windows\s*\{([^{}]*)\}', css).group(1)
        assert 'pointer-events: none' in layer
        z_index = lambda selector: int(re.search(selector + r'\s*\{[^{}]*z-index:\s*(\d+)', css).group(1))
        # the web conference above the presentation overlay (a spectator talks while watching),
        # under the exam end overlay; the toasts above every overlay
        assert z_index(r'\.terminal-windows') < z_index(r'#presentation-overlay') < z_index(r'#webconf-layer')
        assert z_index(r'#webconf-layer') < z_index(r'#webconf-frame') < z_index(r'#exam-ended') < z_index(r'\.toasts')
        assert re.search(r'\.terminal-window\.readonly\s*\{[^{}]*resize: none', css)
        focus = (JS / 'focus.js').read_text(encoding='utf-8')
        assert "const VIEW_KEYS = ['tab', 'terminal', 'question'];" in focus     # no geometry in a focus

    def test_terminals_survive_the_page(self):
        """A terminal session is kept by the agent after its last browser left: the × of a sub-tab
        or a window sends the close frame (the session ends at once), the plain close of a page
        shut down does not; the page joins the user's own sessions again at its first list, before
        the first tab is shown (no terminal opened on top), where they were on this browser (the
        layouts kept in localStorage, read and written under try/catch)."""
        terminal = (JS / 'terminal.js').read_text(encoding='utf-8')
        close = terminal[terminal.index('close({end = false} = {}) {'):]
        assert "socket.send(JSON.stringify({t: 'close'}))" in close[:close.index('this.term.dispose()')]
        terminals = (JS / 'tabs' / 'terminals.js').read_text(encoding='utf-8')
        close_session = terminals[terminals.index('function closeSession('):terminals.index('function undock(')]
        assert 'entry.session.close({end: true})' in close_session
        close_all = terminals[terminals.index('closeAll() {'):terminals.index('getView,')]
        assert 'entry.session.close()' in close_all and 'end: true' not in close_all
        resume = terminals[terminals.index('function resumeOwn()'):terminals.index("return {\n    id: 'terminals'")]
        assert 'r.created_by !== ctx.login' in resume and 'parseFloating(layout.floating)' in resume
        assert 'if (resumed || spectator) {' in resume
        set_sessions = terminals[terminals.index('setSessions(list) {'):terminals.index('openWindow(name) {')]
        assert set_sessions.index('remote = ') < set_sessions.index('resumeOwn();') < set_sessions.index('autoJoin();')
        assert "const LAYOUT_KEY = 'sreweb.terminal_layouts';" in terminals
        for name in ('function loadLayouts()', 'function saveLayouts()'):
            body = terminals[terminals.index(name):]
            assert 'try {' in body[:body.index('\n  }\n')], name
        project = (JS / 'project.js').read_text(encoding='utf-8')
        apply_project = project[project.index('function applyProject('):project.index('function updateSchemaPdfLink()')]
        assert apply_project.index('tabs.terminals.setSessions(state.terminals)') < apply_project.index('selectTab(project.tabs[0])')
        # a page navigated away from stays in the browser's back/forward cache with its sockets open:
        # closed on pagehide (the sessions linger), joined again on a pageshow from the cache
        hide = terminals[terminals.index("window.addEventListener('pagehide'"):terminals.index("window.addEventListener('pageshow'")]
        assert 'entry.session.disconnect()' in hide and 'saveLayouts()' in hide
        show = terminals[terminals.index("window.addEventListener('pageshow'"):]
        assert 'event.persisted' in show[:show.index('});')] and 'entry.session.rejoin()' in show[:show.index('});')]
        assert 'rejoin() {' in terminal and 'disconnect() {' in terminal
