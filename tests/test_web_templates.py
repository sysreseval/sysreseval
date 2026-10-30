"""Tests of the browser side of the web front-end (``web/``): the Jinja2 templates render
without a server, reference existing static files, every ``_("...")`` string of the templates
and of the JavaScript has a French translation, and every JavaScript module parses."""
import re
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
            'language': 'fr', 'instructor': False, 'administrator': False, 'groups': False, 'logout_url': '',
            'site': {'name': '', 'url': '', 'logo_url': ''}}
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
                'pool.html', 'history.html'} <= set(template_names())

    @pytest.mark.parametrize('auth_mode', ['anonymous', 'ldap', 'proxy'])
    def test_login_page(self, auth_mode):
        html = render('login.html', identity=None, auth_mode=auth_mode, error='wrong login or password')
        assert 'wrong login or password' in html
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

    def test_login_error_is_escaped(self):
        html = render('login.html', identity=None, error='<script>alert(1)</script>')
        assert '<script>alert(1)' not in html and '&lt;script&gt;' in html

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

    def test_open_page(self):
        html = render('open.html')
        assert 'id="labs"' in html and 'id="start-button"' in html and '/static/js/open.js' in html
        assert 'id="instructor-mode"' not in html and 'href="/watch"' not in html and 'id="host"' not in html
        assert 'href="/pool"' not in html
        # the instructor's extras: the Instructor mode box and the Host select of the Open page, the Watch
        # and Pool links of every page
        html = render('open.html', instructor=True)
        assert 'id="instructor-mode"' in html and 'href="/watch"' in html and 'Instructor mode' in html
        assert 'id="host"' in html and 'Automatic placement' in html and 'id="host-option" hidden' in html
        assert 'href="/pool"' in html
        html = render('projects.html', instructor=True)
        assert 'href="/watch"' in html and 'href="/pool"' in html and 'href="/history"' not in html
        html = render('projects.html')
        assert 'href="/watch"' not in html and 'href="/pool"' not in html and 'href="/history"' not in html
        # the History link of the administrators (instructors)
        html = render('projects.html', instructor=True, administrator=True)
        assert 'href="/history"' in html and 'href="/watch"' in html

    def test_watch_page(self):
        html = render('watch.html', instructor=True)
        assert 'id="watch"' in html and 'id="watch-filter"' in html and 'id="watch-count"' in html
        assert '/static/js/watch.js' in html and 'href="/watch"' in html
        for key in ('host', 'owner', 'fullname', 'group', 'title', 'started_at', 'last_eval', 'grade', 'mark', 'errors',
                    'terminals', 'managed'):
            assert f'data-sort="{key}"' in html, key
        assert 'data-sort="fullname">Name</th>' in html and 'colspan="13"' in html   # the full name as a column
        assert 'click a row for its last evaluation, a lab for the summary of the lab</span>' in html   # the dialogs
        assert 'a group for that summary' not in html
        assert 'data-login="alice"' in html
        # the group column and select exist, hidden without a configured group source
        assert 'data-groups="false"' in html and 'data-sort="group" hidden>' in html
        assert 'id="watch-group"' in html and 'data-kind="all"' in html and 'data-kind="none"' in html
        assert 'class="watch-group" title="Student group" hidden>' in html
        shown = render('watch.html', instructor=True, groups=True)
        assert 'data-groups="true"' in shown and 'data-sort="group">' in shown
        assert 'a lab for the summary of the lab, a group for that summary restricted to the group</span>' in shown
        assert 'class="watch-group" title="Student group">' in shown
        assert 'data-sort="group" hidden' not in shown and 'title="Student group" hidden' not in shown

    def test_history_page(self):
        events = ('denied', 'login', 'start')
        html = render('history.html', instructor=True, administrator=True, history_database=False, events=events)
        assert 'id="history"' in html and 'id="history-filters"' in html and 'id="history-count"' in html
        assert '/static/js/history.js' in html and 'href="/history"' in html and 'data-login="alice"' in html
        for name in ('login', 'addr', 'event', 'host', 'rln', 'lab', 'since', 'until', 'limit'):
            assert f'name="{name}"' in html, name
        assert '<option value="start">start</option>' in html and '<option value="">All events</option>' in html
        assert 'type="datetime-local"' in html and 'class="grid watch history"' in html
        assert 'id="history-older"' in html and 'id="history-newer"' in html and 'id="history-reset"' in html
        # two tables of ten columns: the events (shown) and the sessions (hidden until chosen)
        events_table, sessions_table = html.split('<table id="history-sessions"')
        assert 'id="history"' in events_table and 'class="grid watch history" data-database' in events_table
        assert events_table.count('<th>') == 10 and events_table.count('colspan="10"') == 1
        assert sessions_table.startswith(' class="grid watch history sessions" hidden>')
        assert sessions_table.count('<th>') == 10 and sessions_table.count('colspan="10"') == 1
        for column in ('Login', 'Name', 'Address', 'Start time', 'End time', 'Duration', 'Requests', 'Projects',
                       'Closed by', 'Events'):
            assert f'<th>{column}</th>' in sessions_table, column
        # the view switch (Sessions first and pressed: the page opens on it) and the filters of the events view alone
        assert 'data-view="sessions" aria-pressed="true">Sessions<' in html
        assert 'data-view="events" aria-pressed="false">Events<' in html
        assert html.index('data-view="sessions"') < html.index('data-view="events"')
        assert html.count('<label class="events-only">') == 4
        assert 'For a session: the time it was closed' in html
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
        assert 'Stop presenting' in html and 'data-groups="false"' in html and 'data-presentation' not in html
        # an instructor may focus the student on the project (the button is shown by project.js on
        # a student's project only); every page has the label of a followed student
        assert 'id="focus-student" class="toggle" aria-pressed="false" hidden' in html and 'Focus student on project' in html
        assert 'id="focus-label" class="presenter-name" hidden' in html
        student = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=False, groups=True)
        assert 'id="present"' not in student and 'id="presentation-bar"' not in student
        assert 'id="focus-student"' not in student and 'id="focus-label"' in student
        assert 'data-groups="true"' in student and 'id="close-project" class="danger">' in student

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
                 render('project.html', host='a01', rln=RLN, api_base=API_BASE, presentation={'id': 'x', 'presenter': 'P'})]
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

class TestJavaScript:
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
