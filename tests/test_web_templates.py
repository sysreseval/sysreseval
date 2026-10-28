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
            'language': 'fr', 'anonymous': False, 'group': ''}
RLN = '20261021153000@@@sre@dhcp.py@@@alice'
API_BASE = '/api/projects/a01/20261021153000%40%40%40sre%40dhcp.py%40%40%40alice'


def environment() -> jinja2.Environment:
    return jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), autoescape=True)


def context(**extra) -> dict:
    """The context of every page (``routes.Routes._page_context``) with the identity callable."""
    base = {'_': lambda text: text, 'identity': IDENTITY, 'auth_mode': 'anonymous', 'languages': LANGUAGES,
            'language': 'fr', 'instructor': False, 'groups': False, 'logout_url': '',
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
                'pool.html'} <= set(template_names())

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
        # proxy mode: Basic auth cannot log out, the button only appears with a logout_url (mod_auth_form)
        assert 'action="/logout"' in render('projects.html')
        assert 'action="/logout"' not in render('projects.html', auth_mode='proxy')
        assert 'action="/logout"' in render('projects.html', auth_mode='proxy', logout_url='/apache-logout')

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
        assert 'href="/watch"' in html and 'href="/pool"' in html
        html = render('projects.html')
        assert 'href="/watch"' not in html and 'href="/pool"' not in html

    def test_watch_page(self):
        html = render('watch.html', instructor=True)
        assert 'id="watch"' in html and 'id="watch-filter"' in html and 'id="watch-count"' in html
        assert '/static/js/watch.js' in html and 'href="/watch"' in html
        for key in ('host', 'owner', 'group', 'title', 'started_at', 'last_eval', 'grade', 'mark', 'errors', 'terminals',
                    'managed'):
            assert f'data-sort="{key}"' in html, key
        assert 'data-login="alice"' in html
        # the group column and select exist, hidden without a configured group source
        assert 'data-groups="false"' in html and 'data-sort="group" hidden>' in html
        assert 'id="watch-group"' in html and 'data-kind="all"' in html and 'data-kind="none"' in html
        assert 'class="watch-group" title="Student group" hidden>' in html
        shown = render('watch.html', instructor=True, groups=True)
        assert 'data-groups="true"' in shown and 'data-sort="group">' in shown
        assert 'class="watch-group" title="Student group">' in shown and ' hidden' not in shown

    def test_pool_page(self):
        html = render('pool.html', instructor=True)
        assert 'id="pool"' in html and 'id="pool-filter"' in html and 'id="pool-count"' in html
        assert 'id="pool-status"' in html and '/static/js/pool.js' in html and 'href="/pool"' in html
        for key in ('name', 'state', 'projects', 'terminals', 'load1', 'occupied_by', 'uptime', 'sre_version'):
            assert f'data-sort="{key}"' in html, key
        assert 'data-login="alice"' in html and 'class="grid watch pool"' in html

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
        student = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=False, groups=True)
        assert 'id="present"' not in student and 'id="presentation-bar"' not in student
        assert 'data-groups="true"' in student and 'id="close-project" class="danger">' in student

    def test_project_page_of_a_spectator(self):
        """The page in the iframe of /present/{id}: the data attributes project.js keys on, no
        control of the presenter's, no navigation out of the frame, the presenter named."""
        html = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=False,
                      presentation={'id': 'pres1', 'presenter': 'Pr. Of'})
        assert 'data-presentation="pres1"' in html and 'data-presenter="Pr. Of"' in html
        assert 'Presented by Pr. Of' in html and 'id="presenter-name"' in html and 'id="ended-banner"' in html
        assert 'id="close-project" class="danger" hidden>' in html
        assert 'id="present"' not in html and 'id="presentation-bar"' not in html
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
