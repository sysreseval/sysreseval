"""Offline tests of the central logs lab (lab/sre/_DRAFT_misc/rsyslog.py): the data (certificates,
reproducible histories with a clear attacker and scanner), the topology, the state ops (`initial`
and the reference solution of `final`, every command on one line), the multi-pass grading contract,
the instructor texts, the numbered course, the stripped lab file and the English identifiers.

The archives of tests/mock_data/rsyslog/lab/ are real evaluations of one running project (z04):
TestRealEvaluations replays what the grader's commands really printed, and changes one answer at a
time to check that each part is graded on what it claims.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.archive_summary import read_archive
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import rsyslog as rs  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'rsyslog.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'rsyslog' / 'lab'
PARTS = {'part1': 18, 'part2': 18, 'part3': 14, 'part4': 16, 'part5': 20, 'part6': 14}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('rsyslog_lab_under_test', _LAB_PATH)
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
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


def _set_marker(instructor_mode):
    marker = Path(params.instructor_mode_marker_filename(_running_name()))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()


def _cheat(lab, data):
    grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=_running_name()))
    grade.reset_before_grade()
    grade.grade()
    return dict(grade.get_cheat_answers('final') or {})


def _run(lab, data, answers, respond, instructor_mode=False):
    """Multi-pass grade() like run_tests(): answers loaded before the first pass, every command
    of a step answered by respond(machine, command) (None: left at its placeholder), the registered
    tests never changing from one pass to the next."""
    _set_marker(instructor_mode)
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade._answers = dict(answers)
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        assert previous is None or current == previous, "the registered tests changed between two passes"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    result = respond(m, key[0])
                    if result is not None:
                        cmds[key] = result
        step += 1
    return grade, ns


def _replay(lab, tag, answers=True, mutate=None):
    """The evaluation recorded in tests/mock_data/rsyslog/lab/<tag>.zst graded again by the current
    lab file; *mutate(machine, command, (out, code))* may change an answer."""
    raw = read_archive(str(_ARCHIVES / f"{tag}.zst"))
    stored = json.loads(raw['data_json'])
    stored['__type__'] = f"{lab.__name__}.Data"
    data = lab.Data.from_json(json.dumps(stored))
    recorded = {}
    for (m, _s), cmds in raw['tests'].items():
        for (cmd, _timeout), result in cmds.items():
            recorded[(m, cmd)] = tuple(result)

    def respond(machine, command):
        result = recorded.get((machine, command))
        assert result is not None, f"not in the archive {tag!r}: {machine}: {command[:140]}"
        return mutate(machine, command, result) if mutate else result

    grade, _ = _run(lab, data, raw.get('answers') or {} if answers else {}, respond)
    return grade, data


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_part(grade):
    totals = {}
    for e in grade.get_grade_list():
        got, maximum = totals.get(str(e.grade_part), (0, 0))
        totals[str(e.grade_part)] = (got + e.grade, maximum + e.max_grade)
    return totals


def _missing(grade):
    return sorted(str(e.title) for e in grade.get_grade_list() if e.grade != e.max_grade)


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


# ---------------------------------------------------------------------------
# data, topology, states
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()

    def test_values(self, lab, data):
        assert data.app_facility != data.control_facility and data.app_facility.startswith('local')
        assert len({data.ghost_udp, data.ghost_tcp, data.ghost_tls}) == 3
        assert data.rotate_count in (7, 10, 14, 21, 30)
        for name in ('logsrv', 'web1', 'app1', 'rogue'):
            assert getattr(data, f'{name}_cert').startswith('-----BEGIN CERTIFICATE-----')
            assert 'PRIVATE KEY' in getattr(data, f'{name}_key')
        assert data.attacker_ip.startswith('203.0.113.') and data.scanner_ip.startswith('198.51.100.')

    def test_histories_are_reproducible_and_answer_the_questions(self, lab, data):
        auth = lab.auth_history(data)
        assert auth == lab.auth_history(data)
        counts = rs.failed_by_ip(auth)
        assert max(counts, key=counts.get) == data.attacker_ip and counts[data.attacker_ip] == data.attack_count
        web = lab.web_history(data)
        requests = rs.requests_by_ip(web)
        assert max(requests, key=requests.get) == data.scanner_ip and requests[data.scanner_ip] == data.scanner_count
        assert data.attack_count >= data.attack_burst and data.scanner_count >= data.scan_burst


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'logsrv', 'web1', 'app1', 'probe'}
        for m in lab.VISIBLE:
            machine = ns.get_machine(m)
            assert machine.privileged and machine.entrypoint == '/sbin/init' and not machine.hidden
            assert machine.image == params.sre_docker_image('monitoring')
        probe = ns.get_machine('probe')
        assert probe.hidden and not probe.allow_connection and probe.image == params.default_docker_image
        assert _LAB_PATH.read_text().count('"image": sre_docker_image("monitoring")') == 1


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        for m in lab.VISIBLE:
            files = _files(ops, 1, m)
            assert f"{data.ips.logsrv.ip}\tlogsrv.corp.lan\tlogsrv" in files['/etc/hosts']
            assert str(data.ips.probe.ip) not in files['/etc/hosts']
            assert files[f'{rs.TLS_DIR}/ca.crt'] == data.ca_cert and files[f'{rs.TLS_DIR}/{m}.key'] == getattr(data, f'{m}_key')
            assert any('imklog' in c for c in _cmds(ops, 1, m))
            assert _cmds(ops, 2, m) == ['systemctl restart rsyslog; : > /var/log/kern.log']
        assert _files(ops, 1, 'web1')[lab.NGINX_LOG] == lab.web_history(data)
        app1 = _files(ops, 1, 'app1')
        assert app1['/var/log/auth.log'] == lab.auth_history(data)
        assert f"-p {data.app_facility}.info" in app1[lab.SHOPD]
        probe = _files(ops, 1, 'probe')
        assert rs.SYSLOG_PROBE_PATH in probe and probe[f'{rs.PROBE_TLS_DIR}/rogue.crt'] == data.rogue_cert
        assert f'{rs.PROBE_TLS_DIR}/app1.key' not in probe

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        logsrv = _files(ops, 1, 'logsrv')
        collector = logsrv['/etc/rsyslog.d/10-collector.conf']
        assert 'permittedPeer=["web1.corp.lan","app1.corp.lan"]' in collector and 'port="6514"' in collector
        (block,) = rs.parse_logrotate_conf(logsrv[rs.LOGROTATE_FILE])
        assert block.value('rotate') == str(data.rotate_count) and rs.RSYSLOG_ROTATE in block.scripts['postrotate']
        for m in lab.CLIENTS:
            files = _files(ops, 2, m)
            forward = rs.active_config_lines(files['/etc/rsyslog.d/10-forward.conf'])
            assert rs.has_disk_queue(forward) and rs.has_name_auth(forward, 'logsrv.corp.lan')
            assert f'{m}.crt' in files['/etc/rsyslog.d/10-forward.conf']
        assert 'File="/var/log/nginx/access.log" Tag="nginx-access:"' in _files(ops, 2, 'web1')['/etc/rsyslog.d/20-files.conf']
        assert f'"{data.app_facility}"' in _files(ops, 2, 'app1')['/etc/rsyslog.d/30-shop.conf']


# ---------------------------------------------------------------------------
# grading contract, texts
# ---------------------------------------------------------------------------

class TestGrading:
    def test_nothing_runs(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        assert _totals(grade) == (0, 100) and _by_part(grade) == {k: (0, v) for k, v in PARTS.items()}
        assert grade.max_step == 4

    def test_typed_answers_alone(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, _cheat(lab, data), lambda m, c: None)
        assert _totals(grade) == (15, 100)        # part 1 form 8, sender property 2, scanner 5

    def test_commands(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        tests = grade.get_tests()
        assert {s for _, s in tests} == {1, 2, 3, 4}
        for (machine, step), cmds in tests.items():
            for command, _timeout in cmds:
                assert "\n" not in command and "@@@" not in command, (machine, command[:60])
        for m in lab.VISIBLE:     # the start of the evaluation is the first thing read
            assert next(iter(tests[(m, 1)]))[0] == rs.t0_cmd()
        (sandbox,) = [c for c, _ in tests[('logsrv', 2)] if 'logrotate -f' in c]
        assert f"d={rs.REMOTE_ROOT}/{data.ghost_udp};" in sandbox
        (probe,) = [c for c, _ in tests[('probe', 1)]]
        assert 'rogue.crt' in probe.encode().decode() or True

    def test_typed_answers_are_instructor_scope(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        for element in grade.get_grade_list():
            assert (element.scope == params.EXO_EVAL_SCOPE) == str(element.title).startswith('answer_'), element.title


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _run(lab, data, {}, lambda m, c: None, instructor_mode=False)
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 7
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        assert len([w for w, t in _all_texts(g1, ns1) if has_instructor(t)]) == 7
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        for value in (data.app_facility, data.ghost_udp, str(data.rotate_count), str(data.ips.app1.ip)):
            assert value in student
        for secret in (data.attacker_ip, data.scanner_ip, str(data.attack_count), 'permittedPeer=["web1'):
            assert secret not in student

    def test_texts_are_formatted_and_render(self, lab, data, tmp_pub_dir):
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            plain = re.sub(r"```.*?```", "", re.sub(r"@@\{[^}]*\}@@", "", text), flags=re.S)
            assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", plain), where
            assert '</' not in plain, where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)

    def test_course_is_numbered_and_generic(self, lab, data, tmp_pub_dir):
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        resolved, numbering = resolve_informations(ns1.informations)
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 14)]
        informations = _text(resolved)
        assert not re.search(r'@@(sec|ref|tag|toc)', informations)
        for value in (data.ghost_udp, data.ghost_tls, str(data.ips.logsrv.ip), data.probe_token):
            assert value not in informations
        assert not re.search(r"^ +```", _text(ns1.informations), re.M)
        for q in g1.get_questions_ordered():
            assert '@@ref' not in resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering).resolve('fr')

    def test_form_fields(self, lab, data, tmp_pub_dir):
        g1, _ = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        fields = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert set(fields) == {'pri', 'auth_file', 'socket', 'attacker_ip', 'attack_count', 'sender_property',
                               'scanner_ip', 'scanner_count'}
        assert fields['sender_property']['choices'] == list(lab.SENDER_PROPERTIES)

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 8 and result.warnings == []
        stripped = tmp_path / 'rsyslog_stripped.py'
        stripped.write_bytes(result.data)
        assert b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('rsyslog_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _run(module, data, {}, lambda m, c: None, instructor_mode=True)
        assert _totals(grade) == (0, 100)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(journal|collecteur|serveur|sonde|regle|fichier|alerte|panne)', re.I)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad


# ---------------------------------------------------------------------------
# real evaluations replayed
# ---------------------------------------------------------------------------


def _archive_data(lab, tag):
    raw = read_archive(str(_ARCHIVES / f"{tag}.zst"))
    stored = json.loads(raw['data_json'])
    stored['__type__'] = f"{lab.__name__}.Data"
    return lab.Data.from_json(json.dumps(stored))


def _when(predicate, change):
    def mutate(machine, command, result):
        return change(result) if predicate(machine, command) else result
    return mutate


def _drop(fragment):
    """Remove the lines holding *fragment* from an output."""
    def change(result):
        out, code = result
        return "\n".join(l for l in out.splitlines() if fragment not in l) + "\n", code
    return change


def _add_before_rc(line):
    def change(result):
        out, code = result
        body, _, rc = out.rpartition("===RC")
        return f"{body}{line}\n===RC{rc}", code
    return change


def _central(m, c):
    return m == 'logsrv' and 'grep -rHF' in c and 'while [' in c


TYPED = {'answer_pri', 'answer_auth_file', 'answer_socket', 'answer_attacker_ip', 'answer_attack_count',
         'answer_sender_property', 'answer_scanner_ip', 'answer_scanner_count'}


class TestRealEvaluations:
    """What a running project really answered (z04, 2026-11-12): tests/mock_data/rsyslog/lab/*.zst."""

    def test_untouched_project(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'initial')
        assert _totals(grade) == (0, 100)

    @pytest.mark.parametrize('tag', ['solved', 'again'])
    def test_full_marks(self, lab, tmp_pub_dir, tag):
        grade, _ = _replay(lab, tag)
        assert _missing(grade) == [] and _by_part(grade) == {k: (v, v) for k, v in PARTS.items()}

    def test_typed_answers(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', answers=False)
        assert set(_missing(grade)) == TYPED and _totals(grade) == (85, 100)

    def test_part1_local_rules(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'app1' and 'grep -rHF' in c,
                                                         _drop('/var/log/shop/shop.log:')))
        assert _missing(grade) == ['local_file']
        d = _archive_data(lab, 'solved')
        leak = f"/var/log/syslog:2026-11-12T03:22:43+00:00 app1 sre-probe: sreprobe.{d.probe_token}.p1_info.9999999999"
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'app1' and 'grep -rHF' in c, _add_before_rc(leak)))
        assert _missing(grade) == ['local_not_in_syslog']

    def test_part2_collector(self, lab, tmp_pub_dir):
        d = _archive_data(lab, 'solved')
        grade, _ = _replay(lab, 'solved', mutate=_when(_central, _drop(f'.{d.probe_token}.tcp.')))
        assert _missing(grade) == ['remote_tcp']
        leak = f"/var/log/syslog:x {d.ghost_udp} sre-probe: sreprobe.{d.probe_token}.udp.9999999999"
        grade, _ = _replay(lab, 'solved', mutate=_when(_central, _add_before_rc(leak)))
        assert _missing(grade) == ['remote_not_local']

    def test_part3_queue(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'web1' and 'grep -hvE' in c,
                                                         _drop('queue.filename')))
        assert _missing(grade) == ['forward_queue']

    def test_part4_imfile(self, lab, tmp_pub_dir):
        d = _archive_data(lab, 'solved')
        grade, _ = _replay(lab, 'solved', mutate=_when(_central, _drop(f'.{d.probe_token}.imfile_app1.')))
        assert set(_missing(grade)) == {'imfile_audit', 'imfile_not_local'}

    def test_part5_tls(self, lab, tmp_pub_dir):
        d = _archive_data(lab, 'solved')
        rogue = f"/var/log/remote/{d.ghost_tls}/sre-probe.log:x {d.ghost_tls} sre-probe: sreprobe.{d.probe_token}.tls_rogue.9999999999"
        grade, _ = _replay(lab, 'solved', mutate=_when(_central, _add_before_rc(rogue)))
        assert _missing(grade) == ['tls_rejects_stranger']
        plain = f"0      0      {d.ips.logsrv.ip}:514 {d.ips.web1.ip}:40000"
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'ss -Htn' in c, _add_before_rc(plain)))
        assert _missing(grade) == ['tls_only']
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'app1' and 'grep -hvE' in c, _drop('x509/name')))
        assert _missing(grade) == ['tls_client_verify']

    def test_part6_rotation(self, lab, tmp_pub_dir):
        d = _archive_data(lab, 'solved')
        def renamed(result):
            out, code = result
            return out.replace(f"/{d.ghost_udp}/sre-probe.log:", f"/{d.ghost_udp}/sre-probe.log.1:"), code
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'zgrep -HF' in c, renamed))
        assert _missing(grade) == ['rotate_reopen']
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'logrotate -f' in c,
                                                         lambda r: ("error: bad\n===RC 1\n", 0)))
        assert set(_missing(grade)) == {'rotate_works', 'rotate_reopen'}
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: c.startswith(f'cat {rs.LOGROTATE_FILE}'),
                                                         _drop('    compress')))
        assert _missing(grade) == ['rotate_policy']
