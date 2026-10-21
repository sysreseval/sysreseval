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

#: the vendored files of `make xterm` are not committed: a missing one is not an error here
VENDORED = 'vendor/xterm/'

# _("...") / _('...') with the usual escapes, in a template or a JavaScript module
TRANSLATED_STRING = re.compile(r"""_\(\s*(['"])((?:\\.|(?!\1).)*)\1""")
STATIC_REFERENCE = re.compile(r"""['"(](/static/[^'")\s]+)""")
# the escapes of a .po string (and of the JavaScript / template literals checked against it)
PO_ESCAPE = re.compile(r'\\(.)')
PO_ESCAPES = {'n': '\n', 't': '\t', '"': '"', "'": "'", '\\': '\\'}

LANGUAGES = [('en', 'English'), ('fr', 'Français')]
IDENTITY = {'login': 'alice', 'fullname': 'Alice Martin', 'email': 'alice@example.org', 'role': 'student',
            'language': 'fr', 'anonymous': False}
RLN = '20261021153000@@@sre@dhcp.py@@@alice'
API_BASE = '/api/projects/a01/20261021153000%40%40%40sre%40dhcp.py%40%40%40alice'


def environment() -> jinja2.Environment:
    return jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), autoescape=True)


def context(**extra) -> dict:
    """The context of every page (``routes.Routes._page_context``) with the identity callable."""
    base = {'_': lambda text: text, 'identity': IDENTITY, 'auth_mode': 'anonymous', 'languages': LANGUAGES,
            'language': 'fr', 'instructor': False}
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
    def test_the_four_pages_exist(self):
        assert {'base.html', 'login.html', 'projects.html', 'open.html', 'project.html'} <= set(template_names())

    @pytest.mark.parametrize('auth_mode', ['anonymous', 'ldap'])
    def test_login_page(self, auth_mode):
        html = render('login.html', identity=None, auth_mode=auth_mode, error='wrong login or password')
        assert '<form method="post" action="/login">' in html
        assert 'name="language"' in html and 'value="fr" selected' in html
        assert 'wrong login or password' in html
        if auth_mode == 'ldap':
            assert 'name="login"' in html and 'name="password"' in html and 'display_name' not in html
        else:
            assert 'name="display_name"' in html and 'name="password"' not in html
        # no session: the language links, no logout form
        assert 'action="/logout"' not in html and 'href="?lang=en"' in html
        assert '<script' not in html.split('<main')[0]   # the page works without JavaScript

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

    def test_project_page(self):
        html = render('project.html', host='a01', rln=RLN, api_base=API_BASE, instructor=True)
        assert f'data-api-base="{API_BASE}"' in html
        assert 'data-rln="20261021153000@@@sre@dhcp.py@@@alice"' in html
        assert 'data-instructor="true"' in html
        assert 'id="tabbar"' in html and 'id="panes"' in html and 'id="closed-banner"' in html
        for control in ('instructor-toggle', 'wrap-toggle', 'font-minus', 'font-plus', 'export-link',
                        'close-project'):
            assert f'id="{control}"' in html
        assert f'href="{API_BASE}/export"' in html and f'{API_BASE}/save' not in html
        assert '/static/vendor/xterm/xterm.js' in html and '/static/vendor/xterm/addon-fit.js' in html
        assert '/static/vendor/xterm/xterm.css' in html and '/static/js/project.js' in html
        assert 'Instructor mode' in html

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
        pages = [render('login.html', identity=None), render('projects.html'), render('open.html'),
                 render('project.html', host='a01', rln=RLN, api_base=API_BASE)]
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
