"""Offline tests of the HTTP reverse proxy lab (lab/sre/_DRAFT_misc2/reverse-proxy.py): the data
(addresses, the CA and the certificate of the site), the topology (three init machines of the
proxy image, closed backends, the hidden probe), the state ops (the backends of `initial`, the
whole solution of `final`, every command on one line, the staged reference configurations), the
grading, the texts (instructor texts in both languages, the numbered course, the stripped lab
file, English identifiers).

No Docker: the grading is **replayed** on archives of real evaluations, captured on 2026-11-11 in
the running lab (tests/mock_data/http_proxy/lab/<situation>.zst: the data of the project and the
output of every command of the grader), in seven situations: a fresh project, the reference
solution, HAProxy stopped on lb1, web4 repaired, the cookie rules removed from the VCL, nginx as
it stands after part 4 (no TLS), HAProxy as it stands after part 8.  A command the grader
registers that is missing from an archive fails the test: the archives must be captured again
when the grader's commands change (see the docstring of `_replay`).
"""
import ast
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
from cryptography import x509

from SRE import params
from SRE.archive_summary import read_archive
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import http_proxy as hp  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc2' / 'reverse-proxy.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'http_proxy' / 'lab'
PARTS = {'part1': 8, 'part2': 10, 'part3': 10, 'part4': 8, 'part5': 10, 'part6': 10, 'part7': 12, 'part8': 12,
         'part9': 10, 'part10': 10}
HAPROXY_ELEMENTS = {'haproxy_frontend', 'haproxy_roundrobin', 'haproxy_health_checks', 'haproxy_forwardfor',
                    'haproxy_stats', 'haproxy_sticky_cookie', 'haproxy_api_acl', 'haproxy_tcp_source', 'haproxy_https'}
INSTRUCTOR_TEXTS = 12        # the organisation question, ten parts, the bonus


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('reverse_proxy_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _running_name():
    return params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')


def _text(t, lang='fr'):
    return t.resolve(lang) if hasattr(t, 'resolve') else str(t)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


class _File:
    """A file op of a state, its content as text."""

    def __init__(self, op):
        self.filename, self.permissions = op.filename, op.permissions
        self.content = op.content.decode() if isinstance(op.content, bytes) else op.content


def _files(ops, step, machine):
    return {op.filename: _File(op) for op in ops.get((step, machine), []) if hasattr(op, 'filename')}


def _replay(lab, tag, tmp_pub_dir, instructor_mode=False, answers=True, mutate=None, module=None):
    """Multi-pass grade() like run_tests(), every command answered by what the archive *tag*
    recorded for it: returns (grade, net_scheme, data).  *mutate(machine, command, (out, code))*
    may change an answer; *answers* False leaves the form empty, 'cheat' fills it with the cheat
    answers of the state `final` instead of the answers stored in the archive.

    To capture the archives again: start the lab on a Docker host, apply `final`, run `sre eval`
    in each situation and copy the archive of each evaluation to
    tests/mock_data/http_proxy/lab/<situation>.zst."""
    raw = read_archive(str(_ARCHIVES / f"{tag}.zst"))
    lab = module or lab
    stored = json.loads(raw['data_json'])
    stored['__type__'] = f"{lab.__name__}.Data"      # the archive names the module of the running lab
    data = lab.Data.from_json(json.dumps(stored))
    recorded = {key: {cmd: result for (cmd, _timeout), result in cmds.items()} for key, cmds in raw['tests'].items()}
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if previous is None:
            if answers == 'cheat':
                grade._answers = dict(grade.get_cheat_answers('final') or {})
            elif answers:
                grade._answers = dict(raw.get('answers') or {})
        else:
            assert current == previous, "the registered tests changed between two passes"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    assert key[0] in recorded.get((m, s), {}), \
                        f"not in the archive {tag!r}: {m} step {s}: {key[0][:140]}"
                    result = tuple(recorded[(m, s)][key[0]])
                    cmds[key] = mutate(m, key[0], result) if mutate else result
        step += 1
    return grade, ns, data


def _totals(grade):
    """(grade, max) of the graded elements and the grade of the bonus ones."""
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.max_grade for e in elements if not e.bonus),
            sum(e.grade for e in elements if e.bonus))


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _lost(grade):
    """Titles of the elements below their maximum."""
    return {str(e.title) for e in grade.get_grade_list() if e.grade != e.max_grade}


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


def _instructor_literals():
    """The tr() string literals used inside the instructor() calls of the lab file."""
    literals = []
    for node in ast.walk(ast.parse(_LAB_PATH.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'instructor':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'id', '') == 'tr' and sub.args \
                        and isinstance(sub.args[0], ast.Constant):
                    literals.append(sub.args[0].value)
    return literals


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        again = lab.Data.from_json(data.to_json())
        assert again.to_json() == data.to_json()
        assert str(again.ips.vip) == str(data.ips.vip) and again.vrrp_id == data.vrrp_id

    def test_addresses(self, lab, data):
        assert not data.nets.wan.overlaps(data.nets.lan)
        wan = ['client', 'probe', 'proxy_wan', 'lb1_wan', 'lb2_wan', 'vip'] + [f"probe_s{i}" for i in range(1, 7)]
        lan = ['proxy_lan', 'lb1_lan', 'lb2_lan', 'web1', 'web2', 'web3', 'web4']
        assert sorted(vars(data.ips)) == sorted(wan + lan)
        assert all(getattr(data.ips, name).ip in data.nets.wan for name in wan)
        assert all(getattr(data.ips, name).ip in data.nets.lan for name in lan)
        assert len({str(getattr(data.ips, name).ip) for name in wan + lan}) == len(wan + lan)
        sources = lab.probe_sources(data)
        assert len(sources) == lab.PROBE_SOURCES and str(data.ips.probe.ip) not in sources

    def test_values(self, lab, data):
        assert re.fullmatch(r"\d\.\d+\.\d+", data.app_version) and data.intranet_secret in lab.INTRANET_WORDS
        assert data.old_slug in lab.OLD_SLUGS and re.fullmatch(r"\d{4}", data.form_code)
        assert re.fullmatch(r"[0-9a-f]{8}", data.form_token) and re.fullmatch(r"[0-9a-f]{12}", data.static_token)
        assert 1 <= data.vrrp_id <= 255 and 1 <= len(data.vrrp_password) <= 8
        assert re.fullmatch(r"[A-Za-z ]+", data.maintenance_sentence) and len(data.maintenance_sentence.split()) == 4
        assert re.fullmatch(r"[A-Za-z0-9]+", data.admin_password + data.stats_password)

    def test_certificates(self, lab, data):
        ca = x509.load_pem_x509_certificate(data.ca_cert.encode())
        site = x509.load_pem_x509_certificate(data.site_cert.encode())
        assert site.issuer == ca.subject and lab.CA_NAME in ca.subject.rfc4514_string()
        names = site.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        assert set(names) == {lab.SITE, lab.API_SITE, lab.APP_SITE}
        assert 'PRIVATE KEY' in data.site_key and 'PRIVATE KEY' in data.ca_key


class TestTopology:
    def test_machines(self, lab, data):
        specs = lab.NetScheme._machine_specs
        assert set(specs) == {'client', 'probe', 'proxy', 'lb1', 'lb2', 'web1', 'web2', 'web3', 'web4'}
        image = params.sre_docker_image('proxy')
        for m in lab.SYSTEMD_MACHINES:
            assert specs[m]['image'] == image and specs[m]['privileged'] and specs[m]['entrypoint'] == '/sbin/init'
        assert specs['client']['image'] == image and specs['client']['bridged'] and specs['client']['x11_host']
        assert 'entrypoint' not in specs['client']
        for m in lab.BACKENDS:
            assert specs[m]['allow_connection'] is False and 'image' not in specs[m] and 'hidden' not in specs[m]
        assert specs['probe'] == {'hidden': True, 'allow_connection': False}
        assert lab.export_kathara_project is False
        # the image name is written in full for `sre preload-images`
        assert 'sre_docker_image("proxy")' in _LAB_PATH.read_text()

    def test_networks(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert lab.NetScheme._topology == {
            'wan': {'client': 0, 'probe': 0, 'proxy': 0, 'lb1': 0, 'lb2': 0},
            'lan': {'proxy': 1, 'lb1': 1, 'lb2': 1, 'web1': 0, 'web2': 0, 'web3': 0, 'web4': 0}}
        assert set(ns.net_config) == set(lab.NetScheme._machine_specs)
        assert len(ns.net_config['probe'][0][0]) == 1 + lab.PROBE_SOURCES and ns.net_config['probe'][0][0][0] == data.ips.probe
        assert [len(ns.net_config[m]) for m in lab.SYSTEMD_MACHINES] == [2, 2, 2]
        assert all(routes == [] for entry in ns.net_config.values() for _, routes in entry)

    def test_hosts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        client, proxy, web1 = ns._hosts('client'), ns._hosts('proxy'), ns._hosts('web1')
        assert f"{data.ips.proxy_wan.ip}\t{lab.SITE} {lab.API_SITE} {lab.OLD_SITE} proxy" in client
        assert f"{data.ips.vip.ip}\t{lab.APP_SITE}" in client and 'web1' not in client
        assert f"{data.ips.web4.ip}\tweb4" in proxy and lab.SITE in proxy
        assert f"{data.ips.web2.ip}\tweb2" in web1 and lab.SITE not in web1
        assert lab.INTRANET_SITE not in client + proxy + web1


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        assert {step for step, _ in ops} == {1}
        for m in lab.BACKENDS:
            files, cmds = _files(ops, 1, m), _cmds(ops, 1, m)
            config = json.loads(files[hp.BACKEND_CONFIG].content)
            assert config['name'] == m and config['apps'] == {'8080': 'shop', '8081': 'api'}
            assert config['vhosts'] == {lab.INTRANET_SITE: data.intranet_secret} and config['version'] == data.app_version
            assert config['form_code'] == data.form_code and config['form_token'] == data.form_token
            assert 'class App' in files[hp.BACKEND_PATH].content
            marker = f"touch {hp.BACKEND_SICK_FILE}" if m == lab.SICK_BACKEND else f"rm -f {hp.BACKEND_SICK_FILE}"
            assert any(c.endswith(marker) for c in cmds) and hp.backend_start_cmd() in cmds
            assert any(f"sre_tcp_server_{lab.BANNER_PORT}" in c for c in cmds)
            assert files['/etc/resolv.conf'].content == '' and files['/etc/hosts'].content == ns._hosts(m)
        for m in ('client', 'probe', 'proxy', 'lb1', 'lb2'):
            assert _files(ops, 1, m)[lab.CA_TRUST_FILE].content == data.ca_cert
            assert any('update-ca-certificates' in c for c in _cmds(ops, 1, m))
        for m in lab.SYSTEMD_MACHINES:
            files = _files(ops, 1, m)
            assert files[lab.CERT_FILE].content == data.site_cert and files[lab.KEY_FILE].content == data.site_key
            assert files[lab.KEY_FILE].permissions == 0o600
            assert "sysctl -w net.ipv4.ip_forward=0" in _cmds(ops, 1, m)
        assert '/etc/resolv.conf' not in _files(ops, 1, 'client')
        assert lab.CA_TRUST_FILE in _files(ops, 1, 'client')['/usr/lib/firefox-esr/distribution/policies.json'].content
        static = _files(ops, 1, 'proxy')[f"{lab.WEB_ROOT}/static/{lab.STATIC_FILE}"].content
        assert f"STATIC_TOKEN={data.static_token}" in static
        # nothing of the solution is given
        assert not any('nginx' in c or 'haproxy' in c or 'varnish' in c or 'keepalived' in c
                       for (_, m), op_list in ops.items() for c in op_list if isinstance(c, str))
        probe_addresses = [c for c in _cmds(ops, 1, 'probe') if c.startswith('ip addr add')]
        assert len(probe_addresses) == 1 + lab.PROBE_SOURCES and str(data.ips.probe) in probe_addresses[0]

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        assert set(ops) == {(1, 'proxy'), (1, 'lb1'), (1, 'lb2'), (1, lab.SICK_BACKEND), (2, 'lb1')}
        proxy = _files(ops, 1, 'proxy')
        assert set(proxy) == {lab.NGINX_SNIPPET_FILE, lab.NGINX_HTTP_FILE, lab.NGINX_SITE_FILE,
                              f"{lab.WEB_ROOT}/{lab.MAINTENANCE_PAGE}", lab.VCL_FILE, lab.APACHE_SITE_FILE, lab.CADDY_FILE}
        assert proxy[lab.NGINX_SITE_FILE].content == ns._solution_nginx_site()
        assert data.maintenance_sentence in proxy[f"{lab.WEB_ROOT}/{lab.MAINTENANCE_PAGE}"].content
        commands = _cmds(ops, 1, 'proxy')
        assert f"htpasswd -bc {lab.HTPASSWD_FILE} {lab.ADMIN_USER} '{data.admin_password}' 2>&1" in commands
        assert "nginx -t 2>&1 && systemctl restart nginx 2>&1" in commands
        for service in ('varnish', 'apache2', 'caddy'):
            assert f"systemctl restart {service} 2>&1" in commands
        for m in lab.LOAD_BALANCERS:
            files = _files(ops, 1, m)
            assert files[lab.HAPROXY_FILE].content == ns._solution_haproxy()
            assert files[lab.KEEPALIVED_FILE].content == ns._solution_keepalived(m)
            cmds = _cmds(ops, 1, m)
            assert cmds.index(ns._solution_haproxy_pem_command()) < next(
                i for i, c in enumerate(cmds) if 'systemctl restart haproxy' in c)
            assert "systemctl restart keepalived 2>&1" in cmds
        assert _cmds(ops, 1, lab.SICK_BACKEND) == [f"touch {hp.BACKEND_SICK_FILE}"]
        assert _cmds(ops, 2, 'lb1') == ["sleep 8"]

    def test_every_command_is_one_line(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for state in ('initial', 'final'):
            for (_, machine), op_list in _state_ops(ns, state).items():
                for op in op_list:
                    if isinstance(op, str):
                        assert '\n' not in op and '@@@' not in op, (state, machine, op[:60])

    def test_nginx_solution_by_part(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        sites = {part: ns._solution_nginx_site(part) for part in range(2, 8)}
        for part, site in sites.items():
            assert site.count('{') == site.count('}'), part
            assert ('shop_app' in site) == (part >= 4) and ('listen 443 ssl http2;' in site) == (part >= 5)
            assert ('location /legacy/' in site) == (part >= 3) and (f"server_name {lab.OLD_SITE};" in site) == (part >= 3)
            assert ('limit_req zone=api' in site) == (part >= 6) and ('auth_basic_user_file' in site) == (part >= 6)
            assert (f"127.0.0.1:{lab.VARNISH_PORT}" in site) == (part >= 7)
            assert 'default_server' in site and 'return 444;' in site
            assert f"include {lab.NGINX_SNIPPET_FILE};" in site
        assert f"proxy_pass http://web1:{lab.SHOP_PORT};" in sites[2] and "return 301 https://$host$request_uri;" in sites[5]
        assert f"return 301 http://{lab.SITE}$request_uri;" in sites[3] and f"return 301 https://{lab.SITE}$request_uri;" in sites[5]
        assert f"allow {data.ips.client.ip};" in sites[6] and f"proxy_pass http://web3:{lab.REPORTS_PORT};" in sites[6]
        assert f"proxy_pass http://web1:{lab.SHOP_PORT}/;" in sites[3] and "proxy_pass http://shop_app/;" in sites[4]
        assert ns._solution_nginx_site() == sites[7]
        assert 'upstream' not in ns._solution_nginx_http(3) and 'limit_req_zone' not in ns._solution_nginx_http(5)
        upstreams = hp.parse_nginx_upstreams(ns._solution_nginx_http())
        app = {member['address']: member for member in upstreams['shop_app']}
        assert app['web1:8080']['weight'] == 2 * app['web2:8080']['weight'] and app['web3:8080']['backup']
        assert lab.SICK_BACKEND not in ns._solution_nginx_http()
        assert 'proxy_http_version' not in ns._solution_nginx_snippet(3) and 'proxy_http_version 1.1;' in ns._solution_nginx_snippet(4)
        assert "gzip on" not in ns._solution_nginx_http() + sites[7]      # already in Debian's nginx.conf

    def test_other_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        basic, full = ns._solution_haproxy_sections(8), ns._solution_haproxy_sections(9)
        for word in ('cookie', 'acl ', 'mode tcp', ':443', 'X-Forwarded-Proto'):
            assert word not in basic and word in full, word
        for text in (basic, full):
            assert 'option httpchk GET /health' in text and 'option forwardfor' in text
            assert f"stats auth {lab.STATS_USER}:{data.stats_password}" in text
            assert all(f"server {m} {m}:{lab.SHOP_PORT}" in text for m in lab.BACKENDS)
        assert ns._solution_haproxy().startswith(lab.HAPROXY_DEBIAN_HEAD) and 'stats socket' in lab.HAPROXY_DEBIAN_HEAD
        confs = {m: hp.parse_keepalived_conf(ns._solution_keepalived(m)) for m in lab.LOAD_BALANCERS}
        master, backup = confs['lb1']['instances']['SHOP'], confs['lb2']['instances']['SHOP']
        assert (master['state'], backup['state']) == ('MASTER', 'BACKUP') and master['priority'] > backup['priority']
        assert master['virtual_router_id'] == backup['virtual_router_id'] == data.vrrp_id
        assert master['virtual_ipaddress'] == [f"{data.ips.vip.ip}/{data.nets.wan.prefixlen}"]
        assert master['auth_pass'] == data.vrrp_password and master['interface'] == 'eth0'
        assert all(hp.keepalived_tracks(conf, 'haproxy') for conf in confs.values())
        vcl = ns._solution_vcl()
        assert vcl.count('{') == vcl.count('}') and 'directors.round_robin()' in vcl and 'return (purge);' in vcl
        assert vcl.count('.probe = health;') == 2 and 'unset req.http.Cookie;' in vcl and 'web3' not in vcl
        assert f"<VirtualHost *:{lab.APACHE_PORT}>" in ns._solution_apache_site()
        assert ns._solution_caddyfile().startswith(f":{lab.CADDY_PORT} {{")


# ---------------------------------------------------------------------------
# grading, replayed on the archives of real evaluations
# ---------------------------------------------------------------------------

class TestGrading:
    def test_reference_solution(self, lab, tmp_pub_dir):
        grade, ns, data = _replay(lab, 'solved', tmp_pub_dir)
        assert _totals(grade) == (100, 100, 10) and _lost(grade) == set()
        parts = {}
        for e in grade.get_grade_list():
            if not e.bonus:
                parts[e.grade_part] = parts.get(e.grade_part, 0) + e.max_grade
        assert parts == PARTS and len(grade.get_grade_list()) == 53
        assert [str(p.title) for p in grade.get_grade_parts()] == [f"part{i}" for i in range(1, 12)]
        assert all(e.grade_part == 'part11' for e in grade.get_grade_list() if e.bonus)
        assert grade.max_step == 2
        tests = {key: [k[0] for k in cmds] for key, cmds in grade.get_tests().items()}
        assert set(tests) == {(m, 1) for m in lab.NetScheme._machine_specs} | {('probe', 2)}
        # the bursts run at step 2, from the probe alone
        assert all(c.startswith(('for i in $(seq', 'rm -f', 'sleep 1.5; curl')) for c in tests[('probe', 2)])
        assert not any('seq 1' in c for c in tests[('probe', 1)])
        for commands in tests.values():
            assert all('\n' not in c and '@@@' not in c for c in commands)

    def test_fresh_project(self, lab, tmp_pub_dir):
        grade, _, _ = _replay(lab, 'initial', tmp_pub_dir)
        assert _totals(grade) == (0, 100, 0)

    def test_registration_pass_gives_nothing(self, lab, data):
        grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=_running_name()))
        grade.reset_before_grade()
        grade.grade()
        assert _totals(grade) == (0, 100, 0)

    def test_nothing_answers(self, lab, tmp_pub_dir):
        dead = lambda machine, command, result: ("curl: (7) Failed to connect\n", 7)  # noqa: E731
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, answers=False, mutate=dead)
        assert _totals(grade) == (0, 100, 0)
        empty = lambda machine, command, result: ("", 0)  # noqa: E731
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, answers=False, mutate=empty)
        assert _totals(grade) == (0, 100, 0)

    def test_haproxy_stopped_on_lb1(self, lab, tmp_pub_dir):
        """The virtual address moved to lb2: part 10 keeps its points, lb1's HAProxy loses its own."""
        grade, _, _ = _replay(lab, 'haproxy_stopped', tmp_pub_dir)
        assert _lost(grade) == HAPROXY_ELEMENTS and _totals(grade) == (78, 100, 10)
        assert all(_by_title(grade)[title].grade == 0 for title in HAPROXY_ELEMENTS)

    def test_web4_repaired(self, lab, tmp_pub_dir):
        """The student made web4 healthy: it must then be served, nothing is lost."""
        grade, _, _ = _replay(lab, 'web4_repaired', tmp_pub_dir)
        assert _totals(grade) == (100, 100, 10)

    def test_varnish_without_the_cookie_rules(self, lab, tmp_pub_dir):
        grade, _, _ = _replay(lab, 'varnish_cookie_rule_removed', tmp_pub_dir)
        assert _lost(grade) == {'cache_catalog', 'cache_header', 'cache_private', 'cache_purge', 'other_nginx_varnish'}
        assert _totals(grade) == (92, 100, 7)
        assert _by_title(grade)['cache_varnish'].grade == 2 and _by_title(grade)['cache_backends'].grade == 2

    def test_nginx_before_tls(self, lab, tmp_pub_dir):
        """nginx as it stands after part 4: parts 2 to 4 are graded over plain HTTP."""
        grade, _, _ = _replay(lab, 'nginx_part4', tmp_pub_dir)
        by_part = {}
        for e in grade.get_grade_list():
            by_part[e.grade_part] = by_part.get(e.grade_part, 0) + e.grade
        assert [by_part[f"part{i}"] for i in range(1, 12)] == [8, 10, 10, 8, 0, 0, 12, 12, 10, 10, 7]
        assert _by_title(grade)['other_nginx_varnish'].grade == 0

    def test_haproxy_after_part_8(self, lab, tmp_pub_dir):
        grade, _, _ = _replay(lab, 'haproxy_part8', tmp_pub_dir)
        assert _lost(grade) == {'haproxy_sticky_cookie', 'haproxy_api_acl', 'haproxy_tcp_source', 'haproxy_https'}
        assert _totals(grade) == (90, 100, 10)

    def test_spoofed_headers(self, lab, tmp_pub_dir):
        """A proxy passing the client's own X-Real-IP / X-Forwarded-For loses the anti-spoofing points."""
        probe = {}

        def trusting(machine, command, result):
            out, code = result
            if '/hello?a=1' in command:
                probe.setdefault('ip', re.search(r"HEADER_X_REAL_IP=(\S+)", out or '') and
                                 re.search(r"HEADER_X_REAL_IP=(\S+)", out).group(1))
                out = re.sub(r"HEADER_X_REAL_IP=\S+", f"HEADER_X_REAL_IP={lab.SPOOFED_ADDRESS}", out)
                out = re.sub(r"(HEADER_X_FORWARDED_FOR=)\S+, \S+", rf"\g<1>{lab.SPOOFED_ADDRESS}", out)
            return out, code

        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=trusting)
        assert _lost(grade) == {'rp_forwarded_for'} and _by_title(grade)['rp_forwarded_for'].grade == 0

    def test_nginx_pool_declarations(self, lab, tmp_pub_dir):
        def plain_pool(machine, command, result):
            out, code = result
            if command.startswith('nginx -T'):
                out = out.replace(' weight=2;', ';').replace(' backup;', ';')
            return out, code

        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=plain_pool)
        assert _lost(grade) == {'lb_weights', 'lb_backup'}

    def test_sick_backend_served(self, lab, tmp_pub_dir):
        """HAProxy without an HTTP health check keeps sending clients to web4."""
        def unchecked(machine, command, result):
            out, code = result
            if machine == 'probe' and f"seq 1 {lab.HA_BURST}" in command:
                out = out.replace('SERVER=web3', 'SERVER=web4', 1)
            if machine == 'lb1' and 'show stat' in command:
                out = out.replace('DOWN', 'UP').replace('L7STS', 'L4OK').replace('L7OK', 'L4OK')
            return out, code

        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=unchecked)
        assert _by_title(grade)['haproxy_health_checks'].grade == 1      # only the requests of /health seen
        assert 'haproxy_roundrobin' in _lost(grade)

    def test_virtual_address_on_both_machines(self, lab, tmp_pub_dir):
        captured = {}

        def split_brain(machine, command, result):
            if command == "ip -j -4 addr show":
                captured.setdefault(machine, result)
                return captured.get('lb1', result)
            return result

        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=split_brain)
        lost = {'ha_virtual_address', 'ha_virtual_service', 'ha_vrrp_adverts', 'ha_track_haproxy'}
        assert _lost(grade) == lost and _by_title(grade)['ha_virtual_address'].grade == 0
        assert _by_title(grade)['ha_vrrp_adverts'].grade == 1             # the adverts carry the right id

    def test_wrong_vrrp_id(self, lab, tmp_pub_dir):
        other = lambda machine, command, result: (re.sub(r"vrid \d+", "vrid 9", result[0] or ''), result[1])  # noqa: E731
        grade, _, data = _replay(lab, 'solved', tmp_pub_dir, mutate=other)
        assert data.vrrp_id != 9 and _lost(grade) == {'ha_vrrp_adverts'}
        assert _by_title(grade)['ha_vrrp_adverts'].grade == 0

    def test_form_scoring(self, lab, tmp_pub_dir):
        grade, _, data = _replay(lab, 'solved', tmp_pub_dir, answers=False)
        form = [t for t, e in _by_title(grade).items() if e.grade_part == 'part1']
        assert _lost(grade) == set(form) == {'http_redirect', 'http_headers', 'http_vhost', 'http_methods'}
        assert _totals(grade) == (92, 100, 10)
        assert all(_by_title(grade)[t].scope == params.EXO_EVAL_SCOPE for t in form)
        assert all(e.scope == params.BOTH_EVAL_SCOPE for t, e in _by_title(grade).items() if t not in form)

    def test_cheat_answers_match_the_fields(self, lab, tmp_pub_dir):
        grade, _, data = _replay(lab, 'solved', tmp_pub_dir)
        fields = {f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        cheat = grade.get_cheat_answers('final')
        answers = {}
        for value in cheat.values():
            answers.update(json.loads(value) if isinstance(value, str) else value)
        assert set(answers) == fields == {'old_status', 'old_location', 'version', 'secret', 'form_get', 'form_token',
                                          'health_web4'}
        assert answers['old_location'] == f"/catalog/{data.old_slug}" and answers['secret'] == data.intranet_secret


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

class TestTexts:
    def test_hashes_and_fragments(self, lab, tmp_pub_dir):
        g0, ns0, data = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=False)
        g1, ns1, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == INSTRUCTOR_TEXTS
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == INSTRUCTOR_TEXTS and 'informations' not in with_fragment
        # the values of the instance are in the organisation question, not in the course
        student = dict(_all_texts(g0, ns0))
        organisation = student['description:Organisation du TP']
        for value in (data.form_code, data.admin_password, data.maintenance_sentence, data.stats_password,
                      str(data.vrrp_id), data.vrrp_password, str(data.ips.vip.ip), str(data.ips.client.ip)):
            assert value in organisation, value
            assert value not in student['informations'] or value == str(data.vrrp_id)
        # the answers of part 1 and the configurations only appear to the instructor
        everything = "\n".join(student.values())
        assert data.intranet_secret not in everything and data.form_token not in everything
        assert 'proxy_set_header Host $host;' not in "\n".join(t for w, t in student.items() if w != 'informations')
        instructor = "\n".join(t for _, t in _all_texts(g1, ns1))
        assert data.intranet_secret in instructor and ns1._solution_vcl().strip() in instructor

    def test_instructor_texts_in_both_languages(self, lab, tmp_pub_dir):
        g1, ns1, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en)
            assert fr != en and ('**Solution.**' in en or '**For the instructor.**' in en), _text(q.title)
            for lang, text in (('fr', fr), ('en', en)):
                assert "{'" not in text and not re.search(r"(?<![{%$])\{[a-z_][a-z_0-9]*\}(?!\})", text), (lang, text[:80])
                markdown_to_html(text, show_instructor=True)
        literals = _instructor_literals()
        assert len(literals) == INSTRUCTOR_TEXTS
        assert set(lab._TRANSLATIONS) == {'en'} and set(lab._TRANSLATIONS['en']) == set(literals)
        assert all(value and value != key for key, value in lab._TRANSLATIONS['en'].items())
        # the title and the description of the reference state are bilingual too (inline)
        assert _text(lab.title, 'en') != _text(lab.title, 'fr')
        description = lab.NetScheme.final._sre_state_description if hasattr(lab.NetScheme.final, '_sre_state_description') \
            else None
        assert description is None or _text(description, 'en') != _text(description, 'fr')

    def test_texts_are_formatted_and_numbered(self, lab, tmp_pub_dir):
        g1, ns1, data = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            for where, text in _all_texts(g1, ns1, lang):
                assert "{'" not in text, (lang, where)
                assert '@@{' not in text or where != 'informations'
                markdown_to_html(text, show_instructor=True)
                markdown_to_html(text, show_instructor=False)
        resolved, numbering = resolve_informations(ns1.informations)
        sections = numbering.sections('fr')
        assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, 11)]
        assert [s.number for s in sections if s.level == 2] == [
            '1.1', '1.2', '1.3', '2.1', '3.1', '3.2', '4.1', '4.2', '4.3', '4.4', '7.1', '8.1', '8.2', '8.3', '8.4',
            '10.1']
        informations = _text(resolved)
        assert '@@' not in informations and 'Organisation du TP' not in informations
        assert '## <a id="haproxy"></a>8. HAProxy' in informations
        assert '### <a id="varnish"></a>7.1. Varnish' in informations
        assert '- [9. Haute disponibilité : VRRP et keepalived](#vrrp)' in informations
        # the course is generic: none of the names or values of the session
        for value in (lab.DOMAIN, str(data.ips.vip.ip), data.admin_password, 'web4'):
            assert value not in informations, value
        for q in g1.get_questions_ordered():
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            for lang in ('fr', 'en'):
                assert '@@ref' not in description.resolve(lang)
        varnish = next(q for q in g1.get_questions_ordered() if 'Varnish' in _text(q.description)[:400]
                       and 'catalogue' in _text(q.title))
        assert re.search(r"sections 7 et 7\.1", resolve_text(TranslatedText.from_value(varnish.description, 'fr'),
                                                              numbering).resolve('fr'))

    def test_form_fields_are_well_formed(self, lab, tmp_pub_dir):
        g1, _, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        fields = 0
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                fields += 1
                assert '}' not in m.group(2)
        assert fields == 7
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert kinds['old_status'] == {'name': 'old_status', 'choices': ['200', '301', '302', '404', '405']}
        assert kinds['version'] == {'name': 'version', 'regex': '[0-9.]+'}

    def test_strip_instructor(self, lab, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == INSTRUCTOR_TEXTS
        stripped = tmp_path / 'reverse_proxy_stripped.py'
        stripped.write_bytes(result.data)
        assert b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('reverse_proxy_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert not any('**Solution.**' in value for value in module._TRANSLATIONS.get('en', {}).values())
        # (the hash of a question covers the languages of its text: without the English instructor
        # texts the stripped file has other hashes, so its own cheat answers fill the form)
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True, module=module, answers='cheat')
        assert _totals(grade) == (100, 100, 10)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(serveur|repartiteur|mandataire|reseau|sonde|panne|secours|adresse|mot|passe|boutique)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=_running_name()))
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        assert len(names) > 100
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
