"""Offline tests of the flow metrology lab (lab/sre/_DRAFT_misc/netflow.py): the data, the topology
(hidden generators with six addresses each), the state ops (`initial`, `restart_traffic`, the
reference solution of `final`, every command on one line), the multi-pass grading contract, the
instructor texts, the numbered course, the stripped lab file and the English identifiers.

The archives of tests/mock_data/netflow/lab/ are real evaluations of one running project (z04):
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

import netflow as nf  # noqa: E402
import traffic  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'netflow.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'netflow' / 'lab'
PARTS = {'part1': 30, 'part2': 25, 'part3': 30, 'part4': 15}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('netflow_lab_under_test', _LAB_PATH)
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
    """The evaluation recorded in tests/mock_data/netflow/lab/<tag>.zst graded again by the current
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
        assert 20000 <= data.collector_port <= 29999 and data.ident in lab.IDENTS
        assert 600 % data.active_timeout == 0 and data.inactive_timeout in (15, 20, 30)
        addresses = [str(getattr(data.ips, n).ip) for n in lab.LAN_HOSTS + ('gen', 'pc', 'router_lan')]
        assert len(set(addresses)) == len(addresses) and all(getattr(data.ips, n) in data.nets.lan for n in lab.LAN_HOSTS)
        assert all(getattr(data.ips, n) in data.nets.wan for n in lab.SERVERS)
        assert lab.beacon_bytes(data) == data.beacon_count * (data.beacon_payload + 28)


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'router', 'collector', 'pc', 'srv', 'gen', 'sink'}
        for m in ('router', 'collector'):
            assert ns.get_machine(m).privileged and ns.get_machine(m).image == params.sre_docker_image('monitoring')
        assert ns.get_machine('gen').hidden and ns.get_machine('sink').hidden
        assert len(ns.net_config['gen'][0][0]) == 7 and len(ns.net_config['sink'][0][0]) == 7
        assert len(ns.net_config['router']) == 3


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        assert 'sysctl -w net.ipv4.ip_forward=1' in _cmds(ops, 1, 'router')
        assert any('sre_traffic_gen.py' in c for c in _cmds(ops, 1, 'sink'))
        assert any('sre_traffic_gen.py' in c for c in _cmds(ops, 2, 'gen'))       # after the servers
        assert nf.SOFTFLOWD_CONF not in _files(ops, 1, 'router') and nf.NFCAPD_CONF not in _files(ops, 1, 'collector')
        assert lab.NetScheme.restart_traffic._sre_state_user_allowed is True

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        conf = _files(ops, 1, 'collector')[nf.NFCAPD_CONF]
        assert conf == f"options='-w /var/cache/nfdump -p {data.collector_port} -t 60 -I {data.ident} -e'\n"
        softflowd = _files(ops, 2, 'router')[nf.SOFTFLOWD_CONF]
        (entry,) = nf.parse_softflowd_cmdline("/usr/sbin/softflowd -i eth0 " + softflowd.split("options='")[1].rstrip("'\n")
                                              + "\n===END\n")
        assert entry["timeouts"]["maxlife"] == data.active_timeout and entry["timeouts"]["icmp"] == data.inactive_timeout
        assert entry["destinations"] == [f"{data.ips.collector.ip}:{data.collector_port}"]
        assert 'nfdump -r' in _cmds(ops, 3, 'collector')[0]


class TestGrading:
    def test_nothing_runs(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        assert _totals(grade) == (0, 100) and _by_part(grade) == {k: (0, v) for k, v in PARTS.items()}
        assert grade.max_step == 1

    def test_typed_answers_alone(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, _cheat(lab, data), lambda m, c: None)
        assert _totals(grade) == (45, 100) and _missing(grade) == sorted(
            str(e.title) for e in grade.get_grade_list() if not str(e.title).startswith('answer_'))

    def test_commands(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        tests = grade.get_tests()
        assert {m for m, _ in tests} == {'router', 'collector'}
        for (machine, step), cmds in tests.items():
            for command, _timeout in cmds:
                assert "\n" not in command and "@@@" not in command
        assert 'tcpdump' in list(tests[('collector', 1)])[-1][0]       # the capture comes last

    def test_typed_answers_are_instructor_scope(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        for element in grade.get_grade_list():
            assert (element.scope == params.EXO_EVAL_SCOPE) == str(element.title).startswith('answer_'), element.title


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _run(lab, data, {}, lambda m, c: None, instructor_mode=False)
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 5
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        assert len([w for w, t in _all_texts(g1, ns1) if has_instructor(t)]) == 5
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        assert str(data.collector_port) in student and data.ident in student
        for secret in (str(data.ips.heavy.ip), str(data.ips.scanner.ip), str(data.ips.beacon.ip), str(data.beacon_port)):
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
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 11)]
        informations = _text(resolved)
        assert not re.search(r'@@(sec|ref|tag|toc)', informations)
        for value in (str(data.collector_port), str(data.ips.collector.ip), data.ident):
            assert value not in informations
        for q in g1.get_questions_ordered():
            assert '@@ref' not in resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering).resolve('fr')

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 5 and result.warnings == []
        stripped = tmp_path / 'netflow_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('netflow_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _run(module, data, {}, lambda m, c: None, instructor_mode=True)
        assert _totals(grade) == (0, 100)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|collecteur|serveur|flux|balise|delai|gabarit|panne)', re.I)
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


def _when(predicate, change):
    def mutate(machine, command, result):
        return change(result) if predicate(machine, command) else result
    return mutate


def _replace(old, new):
    def change(result):
        out, code = result
        assert old in out, old
        return out.replace(old, new), code
    return change


TYPED = {'answer_top_talker', 'answer_top_port', 'answer_top_rate', 'answer_scanner', 'answer_scan_target',
         'answer_scan_ports', 'answer_beacon_port', 'answer_beacon_period', 'answer_beacon_bytes', 'answer_template_id',
         'answer_records_10min', 'answer_max_delay', 'answer_mcq_template', 'answer_mcq_v5', 'answer_sampled_packets'}


class TestRealEvaluations:
    """What a running project really answered (z04, 2026-11-12): tests/mock_data/netflow/lab/*.zst."""

    def test_untouched_project(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'initial')
        assert _totals(grade) == (0, 100)

    @pytest.mark.parametrize('tag', ['solved', 'again'])
    def test_full_marks(self, lab, tmp_pub_dir, tag):
        grade, _ = _replay(lab, tag)
        assert _missing(grade) == [] and _by_part(grade) == {k: (v, v) for k, v in PARTS.items()}

    def test_typed_answers(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', answers=False)
        assert set(_missing(grade)) == TYPED and _totals(grade) == (55, 100)

    def test_the_real_export_datagram(self, lab, tmp_pub_dir):
        raw = read_archive(str(_ARCHIVES / 'solved.zst'))
        (out, _code), = [r for (m, _s), cmds in raw['tests'].items() for (c, _t), r in cmds.items() if 'tcpdump' in c]
        header = nf.netflow_header(nf.parse_tcpdump_hex(out))
        assert header["version"] == 9 and header["count"] >= 1 and nf.SOFTFLOWD_V9_IPV4_TEMPLATE in header["flowset_ids"]

    def test_part1_exporter(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'pidof softflowd' in c, _replace("-i eth0", "-i any")))
        assert set(_missing(grade)) == {'exporter_running', 'exporter_destination', 'exporter_version'}
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'softflowctl' in c, _replace("UDP timeout:", "UDP timeout: 9")))
        assert _missing(grade) == ['timeout_inactive']
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'tcpdump' in c, lambda r: ("===END\n", 0)))
        assert _missing(grade) == ['export_on_wire']

    def test_part2_collector(self, lab, tmp_pub_dir):
        d = _replay(lab, 'solved')[1]
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'pidof nfcapd' in c, _replace(f"-I {d.ident}", "-I other")))
        assert _missing(grade) == ['collector_ident']
        bytes_ = str(lab.beacon_bytes(d))
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'fmt:%tsr' in c and c.startswith('echo'),
                                                         lambda r: (r[0].replace(f"|{bytes_:>8}|", "|       1|"), r[1])))
        assert set(_missing(grade)) == {'witness_flow', 'witness_recent'}

        def later(result):
            out, code = result
            now = nf.parse_now(out)
            return out.replace(f"===NOW {now}", f"===NOW {now + 3600}"), code
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: 'fmt:%tsr' in c or "-printf '%T@" in c, later))
        assert set(_missing(grade)) == {'files_rotating', 'witness_recent'}
