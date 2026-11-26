"""Offline tests of lab/sre/_DRAFT_misc/forward-proxy.py (Squid: authentication and filtering), without Docker.

tests/mock_data/squid/lab/ holds seven real evaluations of one project of the lab (s16, 2026-11-25, image
srefwp/proxy13:1.37 built from images/proxy13 on the published init13:1.36: Squid 6.13 with OpenSSL,
squidGuard 1.6.0, duktape 2.7), exported with ``sre cat --json``: the fresh project (``initial``, 0), the
state ``final`` applied (``final``, 83 + 9 bonus), then the reference ``squid.conf`` with the htpasswd file
instead of LDAP (``htpasswd_only``), with ``ssl_bump splice all`` instead of ``bump all`` (``no_bump``),
without the refusals of part 3 (``no_filtering``), Squid stopped (``squid_stopped``) and ``final`` applied
again (``final_again``).  The commands of the grader depend on the lab data only, so a replay with the data
of an evaluation must register exactly its archived commands and give its archived grades.  After a
deliberate change of the grader's commands, capture them again.
"""
import copy
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import datetime
from ipaddress import IPv4Network
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from SRE import form_spec, params  # noqa: E402
from SRE.informations import resolve_informations, resolve_text  # noqa: E402
from SRE.instructor_text import markdown_to_html, strip_instructor, unwrap_instructor  # noqa: E402
import check_sre_translations  # noqa: E402
import squid  # noqa: E402
import strip_instructor as strip_tool  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'forward-proxy.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'squid' / 'lab'

POINTS = {'part1': 6, 'part2': 7, 'part3': 9, 'part4': 5, 'part5': 9, 'part6': 7, 'part7': 10, 'part8': 9,
          'part9': 9, 'part10': 8, 'part11': 4}
BONUS = 9
TOTAL = sum(POINTS.values())
FORMS = {'log_answers'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('forward_proxy_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _running_name():
    return params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime(2000, 1, 1),
                                       username='check')


def _evaluation(name: str) -> dict:
    return json.loads((_MOCK / f'lab_eval_{name}.json').read_text())


def _data_of(lab, evaluation):
    data = lab.Data.from_dict(copy.deepcopy(evaluation['data']))
    type(data).compute_pre_generate(data.flavor)
    data.compute_post_generate()
    return data


def _outputs(evaluation) -> dict:
    """{(machine, step, command, timeout): (output, code)} of an archived evaluation."""
    return {(batch['machine'], batch['step'], command['command'], command['timeout']):
            (command['output'], command['code'])
            for batch in evaluation['tests'] for command in batch['commands']}


def _replay(lab, evaluation, answers=None, patch=None):
    """grade() pass after pass like run_tests(), the results of each step taken from *evaluation*
    (*patch*: a function changing the {key: (output, code)} table first)."""
    outputs = _outputs(evaluation)
    if patch is not None:
        patch(outputs)
    ns = lab.NetScheme(data=_data_of(lab, evaluation), running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    step, registered = 1, set()
    while True:
        grade.reset_before_grade()
        grade.grade()
        if step == 1 and answers:
            grade._answers = dict(grade.get_cheat_answers(answers) or {})
        if step > grade.max_step:
            break
        for (machine, s), commands in grade.get_tests().items():
            if s != step:
                continue
            for key in list(commands):
                full = (machine, s, key[0], key[1])
                assert full in outputs, f"not in the archived evaluation (capture it again?): {full[:2]} {key[0][:100]}"
                commands[key] = outputs[full]
                registered.add(full)
        step += 1
    missing = set(outputs) - registered
    assert not missing, f"archived commands no longer registered: {[k[2][:80] for k in missing]}"
    return grade


def _totals(grade):
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.max_grade for e in elements if not e.bonus),
            sum(e.grade for e in elements if e.bonus))


def _parts(grade) -> dict:
    result = Counter()
    for e in grade.get_grade_list():
        result[str(e.grade_part)] += e.grade
    return dict(result)


def _lost(grade) -> dict:
    return {str(e.title): e.max_grade - e.grade for e in grade.get_grade_list() if e.grade != e.max_grade}


def _patch_output(machine, step, needle, change):
    """A patch replacing the output of the one command of *machine* at *step* holding *needle*."""
    def patch(outputs):
        keys = [k for k in outputs if k[0] == machine and k[1] == step and needle in k[2]]
        assert len(keys) == 1, [k[2][:80] for k in keys]
        output, code = outputs[keys[0]]
        outputs[keys[0]] = (change(output), code)
    return patch


def _text(value, lang='fr'):
    return value.resolve(lang) if hasattr(value, 'resolve') else (value.get(lang) if isinstance(value, dict) else value)


# ---------------------------------------------------------------------------
# replays of the live evaluations
# ---------------------------------------------------------------------------


class TestReplay:
    def test_initial(self, lab):
        grade = _replay(lab, _evaluation('initial'))
        assert _totals(grade) == (0, TOTAL, 0)

    @pytest.mark.parametrize('name', ['final', 'final_again'])
    def test_final(self, lab, name):
        grade = _replay(lab, _evaluation(name), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, BONUS) and _lost(grade) == {}
        assert _parts(grade) == {**POINTS, 'bonus': BONUS}

    def test_final_without_answers(self, lab):
        grade = _replay(lab, _evaluation('final'))
        assert _totals(grade) == (TOTAL - 4, TOTAL, BONUS) and set(_lost(grade)) == FORMS

    @pytest.mark.parametrize('name, part', [('htpasswd_only', 'part5'), ('no_bump', 'part7'),
                                            ('no_filtering', 'part3')])
    def test_one_part_missing(self, lab, name, part):
        """Each variant of the reference squid.conf loses its part, and only its part."""
        grade = _replay(lab, _evaluation(name), answers='final')
        parts = _parts(grade)
        assert parts[part] == 0, parts
        assert all(points == POINTS.get(p, BONUS) for p, points in parts.items() if p != part), parts

    def test_squid_stopped(self, lab):
        """What does not need Squid: apt and the PAC file on the clients, the log form."""
        grade = _replay(lab, _evaluation('squid_stopped'), answers='final')
        earned = {str(e.title): e.grade for e in grade.get_grade_list() if e.grade}
        assert earned == {'client_apt': 1, 'client_wpad': 2, 'client_pac_proxy': 2, 'client_pac_direct': 1,
                          'log_answers': 4}

    def test_scopes_and_bonus(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in FORMS), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {
            'bonus_delay_limited', 'bonus_delay_others', 'bonus_squidguard_domain', 'bonus_squidguard_url',
            'bonus_squidguard_helper'}

    @pytest.mark.parametrize('patch, lost', [
        # the second request of the fresh 1 MB file missed the cache
        (lambda d: _patch_output('probe', 1, 'cache-$(date', lambda out: out.replace(';hit;detail=match', ';detail=mismatch')),
         {'cache_hit': 2, 'cache_same_object': 1}),
        # the address of the probe in X-Forwarded-For
        (lambda d: _patch_output('probe', 1, '/check/explicit',
                                 lambda out: out.replace('\nHOST=', f"\nHEADER_X_FORWARDED_FOR={d.ips.probe.ip}\nHOST=")),
         {'privacy_xff': 2}),
        # a PAC file that sends everything direct
        (lambda d: _patch_output('probe', 1, squid.PAC_FETCH_MARK, lambda out: out.replace('PROXY proxy.corp.tp:3128', 'DIRECT')),
         {'client_pac_proxy': 2, 'client_pac_direct': 1}),
        # a guest reaches the intranet through the proxy
        (lambda d: _patch_output('guest', 1, f'intranet.corp.tp/check/intercept',
                                 lambda out: 'HTTP/1.1 200 OK\r\n\r\nSERVER=intranet\n\n===SRE_META 1.1 0.01\n===SRE_CODE 200'),
         {'intercept_no_lan': 2}),
        # every line of the access log older than the evaluation
        (lambda d: _patch_output('proxy', 1, 'date +%s.%N', lambda out: str(float(out) + 3600)),
         {'auth_logged': 1, 'bump_logged': 1, 'intercept_https': 2, 'intercept_sni': 1, 'intercept_logged': 1}),
        # bob is not slowed down
        (lambda d: _patch_output('probe', 1, 'dl-bob', lambda out: re.sub(r' [0-9.]+\n?$', ' 0.012\n', out)),
         {'bonus_delay_limited': 2, 'bonus_delay_others': 2}),
        # the password of the service account written in squid.conf
        (lambda d: _patch_output('proxy', 1, 'grep -rlF', lambda out: '1\n'), {'ldap_secret': 1}),
        # another realm
        (lambda d: _patch_output('probe', 1, '/check/noauth', lambda out: out.replace(d.realm, 'Squid proxy-caching web server')),
         {'auth_realm': 1}),
        # casino.tp reached through its IP address (no peek on the SNI)
        (lambda d: _patch_output('probe', 1, f'--connect-to ::{d.ips.site_casino_tp.ip}:443',
                                 lambda out: 'HTTP/1.1 200 OK\r\n\r\nSERVER=internet\n\n===SRE_META 1.1 0.01 200\n===SRE_CODE 200'),
         {'https_sni_blocked': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        data = _data_of(lab, evaluation)
        grade = _replay(lab, evaluation, answers='final', patch=patch(data))
        assert _lost(grade) == lost


# ---------------------------------------------------------------------------
# data, topology, states, reference files
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        nets = [data.nets.lan, data.nets.guest, data.nets.wan]
        assert all(n.is_private and n.prefixlen == 24 for n in nets) and len({str(n) for n in nets}) == 3
        sites = {lab.site_ip(data, s) for s in lab.SITES}
        assert len(sites) == len(lab.SITES) and all(IPv4Network(f"{a}/32").subnet_of(IPv4Network('203.0.113.0/24'))
                                                   for a in sites)
        assert len({data.pw(u) for u in lab.USERS}) == 4 and re.fullmatch(r'CORP Web Access \d{3}', data.realm)
        assert re.fullmatch(r'[0-9A-F]{6}', data.block_code)
        assert data.public_ca_cert.startswith('-----BEGIN CERTIFICATE-----') and data.proxy_ca_key

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert {m.name for m in ns.get_machines()} == {'client', 'proxy', 'ldap', 'intranet', 'guest', 'internet', 'probe'}
        specs = lab.NetScheme._machine_specs
        assert {name for name, spec in specs.items() if spec.get('hidden')} == {'probe'}
        assert all(specs[m].get('entrypoint') == '/sbin/init' and specs[m].get('privileged') for m in ('proxy', 'ldap'))
        assert specs['proxy']['image'] == specs['probe']['image'] == params.sre_docker_image('proxy13')
        assert specs['ldap']['image'] == params.sre_docker_image('identity13')
        assert ns.get_weight() == 23

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        for needle in (f"{lab.BLACKLIST_DIR}/games/domains", lab.SAMPLE_LOG, lab.SITES_CERT, 'slapadd -n 0',
                       f"ip address add {lab.site_ip(data, 'casino.tp')}/32 dev lo", '/usr/local/sbin/sre_http_backend.py'):
            assert needle in text, needle
        ops, _ = ns.compute_state_ops('final')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        for needle in (lab.SQUID_CONF, lab.LDAP_SECRET, lab.PROXY_CA_PEM, lab.NFT_FILE, lab.WPAD_CONF, lab.PROFILE_FILE,
                       lab.APT_PROXY_FILE, lab.CLIENT_PROXY_CA, lab.SQUIDGUARD_CONF, 'security_file_certgen -c'):
            assert needle in text, needle

    def test_reference_squid_conf(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        conf = ns._solution_squid_conf().splitlines()
        assert len(conf) == len(set(line for line in conf if line)) + conf.count('')   # no line twice

        def before(a, b):
            assert conf.index(a) < conf.index(b), (a, b)

        before('http_access deny !lan !guest_net', 'http_access deny games')
        before('http_access deny exe', 'http_access allow guest_net')
        before('http_access deny guest_net lan_servers', 'http_access allow guest_net')
        before('http_access allow guest_net', 'http_access deny !authenticated')
        before('http_access deny !authenticated', 'http_access allow social staff')
        before('http_access allow social staff', 'http_access deny social')
        before('ssl_bump splice nobump', 'ssl_bump bump all')
        before('ssl_bump splice guest_net', 'ssl_bump bump all')
        assert conf[-1] == 'include /etc/squid/conf.d/*.conf' and f"auth_param basic realm {data.realm}" in conf
        assert data.ldap_service_password not in '\n'.join(conf)
        htpasswd = ns._solution_squid_conf(ldap=False)
        assert 'basic_ncsa_auth' in htpasswd and 'ldap' not in htpasswd.lower() and 'acl staff proxy_auth alice' in htpasswd
        assert 'ssl_bump splice all' in ns._solution_squid_conf(bump=False)

    def test_reference_files(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        pac = ns._solution_pac()
        assert f'isInNet(host, "{data.nets.lan.network_address}", "{data.nets.lan.netmask}")' in pac
        assert 'let ' not in pac and f"PROXY {lab.PROXY_NAME}:3128" in pac
        assert f"CORP-BLOCK-{data.block_code}" in ns._solution_block_page() and '%U' in ns._solution_block_page()
        assert 'redirect 302:http://intranet.corp.tp/blocked?url=%u' in ns._solution_squidguard_conf()
        assert not any(line.startswith('flush') for line in ns._solution_nft().splitlines())
        assert 'redirect to :3130' in ns._solution_nft()
        assert 'application/x-ns-proxy-autoconfig' in ns._solution_wpad_nginx()
        assert f"bob:{data.pw('bob')}@{lab.PROXY_NAME}:3128" in ns._solution_profile() and '.corp.tp' in ns._solution_profile()
        assert 'listen 8443 ssl;' in ns._internet_nginx()
        for path in squid.ut1_blacklist_files(lab.BLACKLISTS, lab.BLACKLIST_DIR):
            assert path.startswith(lab.BLACKLIST_DIR + '/')

    def test_log_sample(self, lab, data):
        text, answers = lab.log_sample(data)
        assert (text, answers) == lab.log_sample(data)
        assert set(lab.log_clients(data).values()) <= {str(h) for h in data.nets.lan.hosts()}
        assert answers.top_user in lab.LOG_USERS and answers.top_domain in lab.SITES

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|invite|partie|annuaire|utilisateur|etat|mot_de_passe)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._network_specs)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields]
        assert 'final' in names and 'guests' in names and 'top_domain' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _texts(lab, data, tmp_pub_dir):
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    course, numbering = resolve_informations(ns.informations)
    return course, numbering, grade


class TestTexts:
    def test_course(self, lab, data, tmp_pub_dir):
        course, numbering, _ = _texts(lab, data, tmp_pub_dir)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'proxies', 'squid', 'acl', 'auth', 'https', 'intercept', 'clients', 'cache', 'further']
        text = _text(course)
        assert '@@' not in text
        # no value of the instance and no summary of the questions in the course
        for value in (str(data.nets.lan.network_address), lab.site_ip(data, lab.SITE_NEWS), data.realm, data.block_code,
                      data.pw('alice'), data.ldap_service_password, 'Partie 1', 'webstaff', 'CORP Proxy CA'):
            assert value not in text, value

    def test_instructor_translations(self, lab):
        """Every tr() text is translated (the markup is checked for every lab of the directory by
        test_draft_misc_translations.py), the 13 instructor texts among them."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == set(tr_strings) and all(english.values())
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**')) for v in english.values()) == 13
        assert {k for k in english if english[k] == k} == {'Squid', 'visible_hostname proxy.corp.tp'}
        assert lab.title.resolve('en') == "Squid: web proxy, authentication and filtering"
        assert lab.NetScheme.final._sre_state_description.resolve('en').startswith('Reference solution: Squid')
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)\}', fr)) == set(re.findall(r'\{(\w+)\}', en)), fr[:60]

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        assert len(questions) == 13
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 1
        for q in questions:
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert form_spec.form_fields(fr) == form_spec.form_fields(en)
            assert strip_instructor(fr) != fr, _text(q.title)               # every question has its solution
            assert unwrap_instructor(fr) != unwrap_instructor(en), _text(q.title)

    def test_rendering(self, lab, data, tmp_pub_dir):
        course, numbering, grade = _texts(lab, data, tmp_pub_dir)
        texts = {'informations': _text(course)}
        for index, q in enumerate(grade.get_questions_ordered()):
            texts[f'question {index}'] = _text(resolve_text(q.description, numbering))
        for name, text in texts.items():
            assert "{'" not in text and '@@ref' not in text, name
            assert not re.search(r"(?<![${%@])\{[a-z_][a-z0-9_]*\}", strip_instructor(text)), name
            for show in (False, True):
                assert '```' not in markdown_to_html(text, show_instructor=show), (name, show)

    def test_stripped_lab_file(self, lab, tmp_path):
        source = _LAB_PATH.read_bytes()
        result = strip_tool.strip_source(source)
        assert b'instructor(' not in result.data
        assert not result.warnings, result.warnings
        assert result.calls == 13 and result.translations == 13
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'forward_proxy_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('forward_proxy_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the other texts stays
        assert len(module._TRANSLATIONS['en']) == len(lab._TRANSLATIONS['en']) - 13
        assert not any(v.lstrip().startswith(('**Solution.**', '**For the instructor.**'))
                       for v in module._TRANSLATIONS['en'].values())
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, BONUS)
