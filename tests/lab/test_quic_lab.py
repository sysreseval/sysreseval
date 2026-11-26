"""Offline tests of the QUIC lab (lab/sre/_DRAFT_misc/quic.py): the data (addresses, certificates,
random values), the topology (Debian 13 images, the hidden probe), the state ops, the grading, the
texts (instructor texts in both languages, the numbered course, the stripped lab file, English
identifiers).

No Docker: the grading is **replayed** on archives of real evaluations, captured on 2026-11-18 on
s16 (tests/mock_data/quic/lab/<situation>.zst: the data of the project and the output of every
command of the grader), in six situations: a fresh project, the reference solution, then the
reference solution with one part undone: `quic_bpf` removed from edge, `ssl_early_data` removed
from edge, every UDP port opened on fw instead of 443 only, nginx stopped and disabled on web.  A
command the grader registers that is missing from an archive fails the test: the archives must be
captured again when the grader's commands or the question texts change (see `_replay`).
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

from SRE import form_spec, params
from SRE.archive_summary import read_archive
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'quic.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'quic' / 'lab'
PARTS = {'part1': 12, 'part2': 12, 'part3': 16, 'part4': 8, 'part5': 14, 'part6': 14, 'part7': 12, 'part8': 12}
FORM_POINTS, FORM_BONUS = 41, 2
INSTRUCTOR_TEXTS = 10        # the organisation question, eight parts, the bonus
PART3_SERVICE = {'udp443_nginx', 'h3_get', 'h2_get', 'alt_svc', 'nginx_enabled'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('quic_lab_under_test', _LAB_PATH)
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


def _files(ops, step, machine):
    out = {}
    for op in ops.get((step, machine), []):
        if hasattr(op, 'filename'):
            content = op.content.decode() if isinstance(op.content, bytes) else op.content
            out[op.filename] = (content, op.permissions)
    return out


def _replay(lab, tag, tmp_pub_dir, instructor_mode=False, answers=True, mutate=None, module=None):
    """Multi-pass grade() like run_tests(), every command answered by what the archive *tag*
    recorded for it: returns (grade, net_scheme, data).  *mutate(machine, command, (out, code))*
    may change an answer; *answers* False leaves the forms empty, 'cheat' fills them with the cheat
    answers of the state `final` instead of the answers stored in the archive.

    To capture the archives again: start the lab on a Docker host with the base13 / init13 images,
    run `sre eval` on the fresh project, apply `final`, run `sre eval`, then undo one part at a
    time (and apply `final` again), and copy the archive of each evaluation to
    tests/mock_data/quic/lab/<situation>.zst."""
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


def _lost(grade):
    """Titles of the elements below their maximum."""
    return {str(e.title) for e in grade.get_grade_list() if e.grade != e.max_grade}


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


def _tr_literals():
    import check_sre_translations
    return check_sre_translations.get_tr_strings(ast.parse(_LAB_PATH.read_text()))


def _instructor_literals():
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

    def test_addresses(self, lab, data):
        assert data.nets.wan in lab.WAN_NETWORKS and data.nets.corp.is_private
        wan = [data.ips.client, data.ips.ref, data.ips.web, data.ips.edge, data.ips.ns, data.ips.fw_wan, data.ips.probe]
        assert len({ip.ip for ip in wan}) == 7 and all(ip.ip in data.nets.wan for ip in wan)
        assert data.ips.fw_corp.ip in data.nets.corp and data.ips.pc.ip in data.nets.corp

    def test_values(self, lab, data):
        assert 40 <= data.max_streams <= 250 and data.max_streams not in (100, 128)
        assert 20 <= data.idle_timeout <= 90 and data.idle_timeout not in (60, 65, 75)
        assert re.fullmatch(r'quic-[0-9a-f]{8}', data.web_token)
        assert len(data.h3_secret.split()) == 4 and ',' not in data.h3_secret

    def test_certificates(self, lab, data):
        ca = x509.load_pem_x509_certificate(data.ca_cert.encode())
        for pem, name in ((data.news_cert, lab.NEWS), (data.www_cert, lab.WWW), (data.cdn_cert, lab.CDN)):
            cert = x509.load_pem_x509_certificate(pem.encode())
            assert cert.issuer == ca.subject
            assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName) == [name]


class TestTopology:
    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert set(specs) == {'client', 'ref', 'web', 'edge', 'ns', 'fw', 'pc', 'probe'}
        # every machine names its Debian 13 image (the lab was written when the default image was Debian 12)
        assert all(spec['image'].split(':')[0] in ('sysreseval/base13', 'sysreseval/init13') for spec in specs.values())
        for m in ('ref', 'web', 'edge', 'ns'):
            assert specs[m]['image'].startswith('sysreseval/init13:') and specs[m]['privileged']
            assert specs[m]['entrypoint'] == '/sbin/init'
        assert specs['probe']['hidden'] and not specs['probe']['allow_connection']
        assert not specs['ref']['allow_connection']
        assert specs['client']['bridged'] and specs['client']['x11_host']
        assert lab.export_kathara_project is False

    def test_networks(self, lab):
        assert lab.NetScheme._topology == {
            'wan': {'client': 0, 'ref': 0, 'web': 0, 'edge': 0, 'ns': 0, 'fw': 0, 'probe': 0},
            'corp': {'fw': 1, 'pc': 0}}

    def test_hosts_file(self, lab, data):
        hosts = lab.hosts_file(data, 'pc')
        for line in (f"{data.ips.ref.ip}\tref {lab.NEWS}", f"{data.ips.web.ip}\tweb {lab.WWW}",
                     f"{data.ips.edge.ip}\tedge {lab.CDN}", "127.0.1.1\tpc"):
            assert line in hosts


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for m in ('client', 'pc', 'probe'):
            assert '/usr/local/bin/quic-client' in _files(ops, 1, m)
        for m in lab.NetScheme._machine_specs:
            files = _files(ops, 1, m)
            assert files['/etc/resolv.conf'][0] == f"nameserver {data.ips.ns.ip}\n"
            assert files[lab.CA_FILE][0] == data.ca_cert
        ref = _files(ops, 1, 'ref')
        assert ref[lab.NEWS_CONF][0] == lab.news_conf(data)
        assert f"http3_max_concurrent_streams {data.max_streams};" in ref[lab.NEWS_CONF][0]
        assert f"keepalive_timeout {data.idle_timeout}s;" in ref[lab.NEWS_CONF][0]
        assert ref[f"{lab.NEWS_ROOT}/h3-secret.txt"][0] == data.h3_secret + "\n"
        assert ref[f"{lab.SSL_DIR}/{lab.NEWS}.key"][1] == 0o600
        edge = _files(ops, 1, 'edge')
        assert edge[lab.CDN_CONF][0] == lab.cdn_conf(tuned=False)
        assert any(f"worker_processes {lab.EDGE_WORKERS};" in c for c in _cmds(ops, 1, 'edge'))
        web = _files(ops, 1, 'web')
        assert lab.WEB_CONF not in web and data.web_token in web[f"{lab.WEB_ROOT}/index.html"][0]
        ns_files = _files(ops, 1, 'ns')
        assert 'HTTPS' not in ns_files[lab.ZONE_QUIC][0] and 'HTTPS' in ns_files[lab.ZONE_NEWS][0]
        assert _files(ops, 1, 'fw')[lab.FW_CONF][0] == lab.render_fw_ruleset(quic=False)

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        web = _files(ops, 1, 'web')
        assert web[lab.WEB_CONF][0] == lab.web_conf() and 'listen 443 quic reuseport;' in web[lab.WEB_CONF][0]
        assert web['/etc/caddy/Caddyfile'][0] == lab.caddyfile() and web[f"/etc/caddy/{lab.WWW}.key"][1] == 0o600
        assert 'alpn="h3,h2"' in _files(ops, 1, 'ns')[lab.ZONE_QUIC][0]
        assert 'udp dport 443 accept' in _files(ops, 1, 'fw')[lab.FW_CONF][0]
        edge = _files(ops, 1, 'edge')[lab.CDN_CONF][0]
        for line in ("quic_retry on;", f"quic_host_key {lab.HOST_KEY};", "ssl_early_data on;",
                     "add_header Early-Data $ssl_early_data always;", "if ($ssl_early_data) { return 425; }"):
            assert line in edge, line
        assert any("quic_bpf on;" in c for c in _cmds(ops, 1, 'edge'))
        capture = ' '.join(_cmds(ops, 1, 'client'))
        assert f"SSLKEYLOGFILE={lab.KEYLOG}" in capture and f"-w {lab.PCAP}" in capture and 'kill -INT' in capture

    def test_every_command_is_one_line(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for state in ('initial', 'final'):
            ops = _state_ops(ns, state)
            for (step, machine) in ops:
                for cmd in _cmds(ops, step, machine):
                    assert '\n' not in cmd, (state, machine, cmd[:80])


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_parts(self, lab, tmp_pub_dir):
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir)
        parts = {}
        for e in grade.get_grade_list():
            if not e.bonus:
                parts[e.grade_part] = parts.get(e.grade_part, 0) + e.max_grade
        assert parts == PARTS and len(grade.get_grade_list()) == 31
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {'caddy_h3', 'q_version_negotiation'}

    def test_reference_solution(self, lab, tmp_pub_dir):
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir)
        assert _totals(grade) == (100, 100, 7) and not _lost(grade)
        assert not grade._errors

    def test_fresh_project(self, lab, tmp_pub_dir):
        grade, _, _ = _replay(lab, 'initial', tmp_pub_dir)
        assert _totals(grade) == (0, 100, 0)

    def test_registration_pass_gives_nothing(self, lab, data):
        grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=_running_name()))
        grade.reset_before_grade()
        grade.grade()
        assert _totals(grade) == (0, 100, 0)

    def test_forms_alone(self, lab, tmp_pub_dir):
        empty, _, _ = _replay(lab, 'solved', tmp_pub_dir, answers=False)
        assert _totals(empty) == (100 - FORM_POINTS, 100, 7 - FORM_BONUS)
        cheat, _, _ = _replay(lab, 'initial', tmp_pub_dir, answers='cheat')
        assert _totals(cheat) == (FORM_POINTS, 100, FORM_BONUS)

    @pytest.mark.parametrize('tag, lost, total', [
        ('edge_no_bpf', {'migration'}, 92),
        ('edge_no_early_data', {'early_data', 'order_425'}, 92),
        ('fw_all_udp', {'udp_alt_blocked', 'fw_persistent'}, 96),
        ('web_nginx_stopped', PART3_SERVICE, 87),
    ])
    def test_one_part_undone(self, lab, tmp_pub_dir, tag, lost, total):
        grade, _, _ = _replay(lab, tag, tmp_pub_dir)
        assert _lost(grade) == lost and _totals(grade) == (total, 100, 7)

    def test_part5_gated_on_quic(self, lab, tmp_pub_dir):
        """UDP 8443 blocked and HTTP/2 passing are worth nothing while HTTP/3 does not pass."""
        def no_quic(machine, command, result):
            if machine == 'pc' and '--http3-only' in command and ':443 ' in command:
                return "curl: (28) Connection timed out\n\n===SRE_META 0 5.0\n===SRE_CODE 000", 28
            return result
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=no_quic)
        assert _lost(grade) == {'h3_through_fw', 'udp_alt_blocked', 'tcp_still', 'fw_persistent'}

    def test_host_key_mode(self, lab, tmp_pub_dir):
        def readable(machine, command, result):
            if machine == 'edge' and 'quic_host_key' in command and command.startswith('for f'):
                return result[0].replace(' 600 ', ' 644 '), result[1]
            return result
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=readable)
        assert _lost(grade) == {'host_key'}

    def test_capture_of_another_server(self, lab, tmp_pub_dir):
        """A capture without traffic between client and ref gives nothing in part 2."""
        def elsewhere(machine, command, result):
            if machine == 'probe' and command.startswith('tshark'):
                return '', 0
            return result
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, mutate=elsewhere)
        assert _lost(grade) == {'capture_present', 'capture_decrypts'}

    def test_cheat_answers_match_the_fields(self, lab, tmp_pub_dir):
        grade, _, data = _replay(lab, 'solved', tmp_pub_dir)
        fields = {f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        answers = {}
        for value in grade.get_cheat_answers('final').values():
            answers.update(json.loads(value) if isinstance(value, str) else value)
        assert set(answers) == fields and len(fields) == 36
        assert answers['secret'] == data.h3_secret and answers['max_streams'] == str(data.max_streams)
        assert answers['idle'] == str(data.idle_timeout * 1000) and answers['rrtype'] == '65'

    def test_choices_table(self, lab):
        for name, (options, index) in lab.CHOICES.items():
            assert 0 <= index < len(options) and len(set(options)) == len(options), name
            assert not any(c in o for o in options for c in '|{}@'), name
        # the right answers are not all in the same position
        assert len({index for _, index in lab.CHOICES.values()}) >= 3


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
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        # the values to find are never given to the students
        for value in (data.h3_secret, f"{data.max_streams}", f"{data.idle_timeout * 1000}", 'quic_bpf on;\n'):
            assert value not in student, value
        instructor = "\n".join(t for _, t in _all_texts(g1, ns1))
        assert data.h3_secret in instructor and str(data.idle_timeout * 1000) in instructor

    def test_instructor_texts_in_both_languages(self, lab, tmp_pub_dir):
        g1, _, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en)
            assert fr != en and ('**Solution.**' in en or '**For the instructor.**' in en), _text(q.title)
            for lang, text in (('fr', fr), ('en', en)):
                assert "{'" not in text and not re.search(r"(?<![{%$])\{[a-z_][a-z_0-9]*\}(?!\})", text), (lang, text[:80])
                markdown_to_html(text, show_instructor=True)
        literals = _instructor_literals()
        assert len(literals) == INSTRUCTOR_TEXTS
        # every text is translated (the instructor ones and the others): the markup is checked for every lab
        # of the directory by test_draft_misc_translations.py
        english = lab._TRANSLATIONS['en']
        assert set(lab._TRANSLATIONS) == {'en'} and set(english) == _tr_literals() and set(literals) <= set(english)
        assert all(value and value != key for key, value in english.items())
        # the dropdowns of the English forms show English labels and store the French options
        for name, (options, index) in lab.CHOICES.items():
            assert len(lab.CHOICES_EN[name]) == len(options) and lab._ok(name, 'en') == lab.CHOICES_EN[name][index]
            assert form_spec.form_fields(lab._dd(name, 'en')) == form_spec.form_fields(lab._dd(name))
        assert _text(lab.title, 'en') != _text(lab.title, 'fr')
        description = lab.NetScheme.final._sre_state_description
        assert _text(description, 'en') != _text(description, 'fr')

    def test_course_is_numbered(self, lab, tmp_pub_dir):
        g1, ns1, data = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            for where, text in _all_texts(g1, ns1, lang):
                assert "{'" not in text, (lang, where)
                markdown_to_html(text, show_instructor=True)
                markdown_to_html(text, show_instructor=False)
        resolved, numbering = resolve_informations(ns1.informations)
        sections = numbering.sections('fr')
        assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, 16)]
        assert [s.number for s in sections if s.level == 2] == ['3.1', '3.2', '3.3']
        informations = _text(resolved)
        assert '@@' not in informations and 'Organisation du TP' not in informations
        assert '## <a id="cid"></a>8. Identifiants de connexion et migration' in informations
        # the course is generic: no value of the session
        for value in (str(data.ips.ref.ip), data.h3_secret, data.web_token):
            assert value not in informations, value
        for q in g1.get_questions_ordered():
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            for lang in ('fr', 'en'):
                assert '@@ref' not in description.resolve(lang)

    def test_form_fields_are_well_formed(self, lab, tmp_pub_dir):
        g1, _, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True)
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert len(kinds) == 36
        for name, (options, _) in lab.CHOICES.items():
            assert kinds[name] == {'name': name, 'choices': options}, name
        assert kinds['max_streams'] == {'name': 'max_streams', 'regex': '[0-9]+'}

    def test_strip_instructor(self, lab, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == INSTRUCTOR_TEXTS
        stripped = tmp_path / 'quic_stripped.py'
        stripped.write_bytes(result.data)
        assert b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('quic_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(set(_instructor_literals()))
        grade, _, _ = _replay(lab, 'solved', tmp_pub_dir, instructor_mode=True, module=module, answers='cheat')
        assert _totals(grade) == (100, 100, 7)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(serveur|reseau|sonde|parefeu|adresse|secret_|jeton|flux|chiffr)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=_running_name()))
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        assert len(names) > 90
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
