"""Offline tests of the Prometheus lab (lab/sre/_DRAFT_misc/prometheus.py): the data, the
topology, the state ops (`initial`, the incidents and `repair`, the reference solution of `final`,
every command on one line), the reference files and expressions, the multi-pass grading contract,
the instructor texts, the numbered course, the stripped lab file and the English identifiers.

The archives of tests/mock_data/prometheus/lab/ are real evaluations of one running project (z04:
untouched, after `final`, during the incidents, repaired): TestRealEvaluations replays what the
grader's commands really printed, and changes one answer at a time to check that each part is
graded on what it claims.
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

import prometheus as pm  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'prometheus.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'prometheus' / 'lab'
PARTS = {'part1': 10, 'part2': 16, 'part3': 22, 'part4': 10, 'part5': 10, 'part6': 16, 'part7': 16}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('prometheus_lab_under_test', _LAB_PATH)
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
    """The cheat answers of `final`: collected on a throwaway pass (they are declared by grade())."""
    grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=_running_name()))
    grade.reset_before_grade()
    grade.grade()
    return dict(grade.get_cheat_answers('final') or {})


def _run(lab, data, answers, respond, instructor_mode=False):
    """Multi-pass grade() like run_tests(): the answers are loaded before the first pass, every
    command of a step is answered by respond(machine, command) -> (output, code) | None (left at
    its placeholder), and the registered tests never change from one pass to the next."""
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


def _replay(lab, tag, answers=True, mutate=None, strict=True):
    """The evaluation recorded in tests/mock_data/prometheus/lab/<tag>.zst, graded again by the
    current lab file: returns (grade, data).  *mutate(machine, command, (out, code))* may change an
    answer; *answers* False leaves the forms empty.

    To capture the archives again: start the lab on a Docker host, run `sre eval` in each situation
    (untouched; after `sre state … final` + the cheat answers; after `incident_node`; after
    `incident_queue`; after `repair`) and copy the archive of each evaluation here."""
    raw = read_archive(str(_ARCHIVES / f"{tag}.zst"))
    stored = json.loads(raw['data_json'])
    stored['__type__'] = f"{lab.__name__}.Data"      # the archive names the module of the running lab
    data = lab.Data.from_json(json.dumps(stored))
    recorded = {key: {cmd: result for (cmd, _timeout), result in cmds.items()} for key, cmds in raw['tests'].items()}

    def respond(machine, command):
        for (m, _s), cmds in recorded.items():
            if m == machine and command in cmds:
                result = tuple(cmds[command])
                return mutate(machine, command, result) if mutate else result
        if strict:
            raise AssertionError(f"not in the archive {tag!r}: {machine}: {command[:140]}")
        return None

    grade, _ = _run(lab, data, raw.get('answers') or {} if answers else {}, respond)
    return grade, data


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


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
# data, topology
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()

    @pytest.mark.parametrize('seed', range(40))
    def test_values(self, lab, seed):
        import random
        random.seed(seed)
        d = lab.Data.generate()
        assert 7 <= len(d.requests) <= 9
        ranges = {(m, p, s): rates for m, p, s, rates, _ in lab.CATALOGUE}
        for method, path, status, rate in d.requests:
            low, high = ranges[(method, path, status)]
            assert low <= rate <= high and isinstance(rate, int)
        requests = lab.app_requests(d)
        by_path = sorted(pm.expected_rates(requests, ("path",)).values(), reverse=True)
        assert by_path[0] >= 1.2 * by_path[1]
        assert 0.02 <= pm.expected_error_ratio(requests) <= 0.09
        assert d.queue_low + 10 <= d.queue_high <= d.queue_threshold - 8 < d.orders_capacity
        assert d.retention_days in (3, 5, 10, 15) and d.backup_size % 1048576 == 0
        # the 95th percentile falls in a finite bucket
        assert pm.expected_quantile(requests, lab.BUCKETS, lab.PROFILES[d.latency_profile], 0.95) < 2.5
        assert not d.nets.lan.overlaps(d.nets.dmz)

    def test_profiles_sum_to_one(self, lab):
        for profile in lab.PROFILES:
            for shares in profile.values():
                assert len(shares) == len(lab.BUCKETS) + 1 and sum(shares) == pytest.approx(1.0)

    def test_application_configuration(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        config = json.loads(ns.app_config())
        assert config["metrics_path"] == lab.APP_METRICS_PATH and config["listen"] == ["0.0.0.0", lab.APP_PORT]
        assert config["incident"] == {"queue": "orders", "value": data.queue_threshold + 12}
        assert config["queues"]["orders"]["high"] == data.queue_high
        assert [r["rate"] for r in config["requests"]] == [r[3] for r in data.requests]


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'prom', 'pc', 'chat', 'router', 'web1', 'db1'}
        for m in lab.SYSTEMD_MACHINES:
            machine = ns.get_machine(m)
            assert machine.privileged and machine.entrypoint == '/sbin/init'
            assert machine.image == params.sre_docker_image('monitoring')
        assert ns.get_machine('pc').bridged and ns.get_machine('pc').x11_host
        assert ns.get_machine('chat').image == params.default_docker_image
        router = ns.get_machine('router')
        assert not router.allow_connection and router.image == params.sre_docker_image('monitoring')
        assert not any(ns.get_machine(m).hidden for m in ns.get_machine_names())

    def test_image_is_written_literally(self):
        assert _LAB_PATH.read_text().count('"image": sre_docker_image("monitoring")') >= 2

    def test_routes_and_names(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert str(ns.net_config['prom'][0][1][0][1]) == str(data.ips.router_lan.ip)
        assert str(ns.net_config['db1'][0][1][0][1]) == str(data.ips.router_dmz.ip)
        assert ns.names('web1') == ('web1', 'web1.shop.lan', str(data.ips.web1.ip))
        assert 'localhost' in ns.names('prom') and str(data.ips.router_dmz.ip) in ns.names('router-dmz')


# ---------------------------------------------------------------------------
# states and reference files
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        for m in ns.get_machine_names():
            hosts = _files(ops, 1, m)['/etc/hosts']
            assert f"{data.ips.prom.ip}\tprom\tprom.shop.lan" in hosts and f"{data.ips.router_dmz.ip}\trouter-dmz" in hosts
            assert ('/etc/resolv.conf' in _files(ops, 1, m)) == (m != 'pc')
        assert f"rocommunity {data.snmp_community} default\n" in _files(ops, 1, 'router')['/etc/snmp/snmpd.conf']
        web1 = _files(ops, 1, 'web1')
        assert json.loads(web1[pm.METRICS_APP_CONFIG]) == json.loads(ns.app_config())
        assert web1[pm.METRICS_APP_PATH] == (_REPO / 'lib' / 'metrics_app.py').read_text()
        assert any('systemctl enable --now shop' in c for c in _cmds(ops, 1, 'web1'))
        assert _files(ops, 1, 'chat')[pm.SINK_PATH] == (_REPO / 'lib' / 'webhook_sink.py').read_text()
        assert any('sre_webhook_sink.py serve' in c for c in _cmds(ops, 1, 'chat'))
        prom = _files(ops, 1, 'prom')
        assert 'community: public' in prom[pm.SNMP_YML] and pm.PROBE_PATH in prom
        assert _cmds(ops, 1, 'prom')[-1] == 'systemctl start prometheus'
        assert pm.PROMETHEUS_YML not in prom and pm.BLACKBOX_YML not in prom      # Debian's files stay

    def test_incidents_and_repair(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        node = _cmds(_state_ops(ns, 'incident_node'), 1, 'db1')
        assert len(node) == 1 and 'systemctl stop prometheus-node-exporter' in node[0] and lab.INCIDENT_MARK in node[0]
        assert _files(_state_ops(ns, 'incident_queue'), 1, 'web1') == {'/var/lib/shop/mode': 'queue\n'}
        repair = _state_ops(ns, 'repair')
        assert f'[ -f {lab.INCIDENT_MARK} ] && systemctl start prometheus-node-exporter' in _cmds(repair, 1, 'db1')[0]
        assert 'systemctl start shop' in _cmds(repair, 1, 'web1')[0]
        assert 'sre_webhook_sink.py serve' in _cmds(repair, 1, 'chat')[0]
        for name in ('incident_node', 'incident_queue', 'repair'):
            assert getattr(lab.NetScheme, name)._sre_state_user_allowed is True
        assert lab.NetScheme.final._sre_state_user_allowed is False

    def test_final(self, lab, data):
        yaml = pytest.importorskip("yaml")
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        prom = _files(ops, 1, 'prom')
        assert prom[pm.PROMETHEUS_DEFAULTS].endswith(f'ARGS="--storage.tsdb.retention.time={data.retention_days}d"\n')
        assert prom[pm.ALERTMANAGER_DEFAULTS].endswith('ARGS="--cluster.listen-address="\n')
        config = yaml.safe_load(prom[pm.PROMETHEUS_YML])
        jobs = {j["job_name"]: j for j in config["scrape_configs"]}
        assert set(jobs) == {"prometheus", "node", "app", "blackbox_http", "blackbox_icmp", "snmp"}
        assert jobs["app"]["scrape_interval"] == "5s" and jobs["app"]["metrics_path"] == lab.APP_METRICS_PATH
        assert jobs["node"]["static_configs"][1] == {"targets": ["db1:9100"], "labels": {"role": "db"}}
        assert jobs["snmp"]["static_configs"][0]["targets"] == [str(data.ips.router_lan.ip)]
        assert jobs["blackbox_icmp"]["relabel_configs"][2] == {"target_label": "__address__",
                                                               "replacement": "localhost:9115"}
        assert config["rule_files"] == ["/etc/prometheus/rules/*.yml"]
        rules = yaml.safe_load(prom[lab.RULES_FILE])["groups"][0]["rules"]
        assert [r.get("record") or r.get("alert") for r in rules] == [lab.RECORD_NAME, "Watchdog", "InstanceDown",
                                                                       "QueueTooLong"]
        assert rules[3]["expr"] == f'shop_queue_length{{queue="orders"}} > {data.queue_threshold}'
        assert "{{ $labels.instance }}" in rules[2]["annotations"]["summary"]
        blackbox = yaml.safe_load(prom[pm.BLACKBOX_YML])["modules"]
        assert set(pm.DEBIAN_BLACKBOX_MODULES) < set(blackbox)
        assert blackbox["http_shop"]["http"]["fail_if_body_not_matches_regexp"] == ["^OK"]
        assert yaml.safe_load(prom[pm.SNMP_YML])["if_mib"]["auth"]["community"] == data.snmp_community
        am = yaml.safe_load(prom[pm.ALERTMANAGER_YML])
        assert am == lab.NetScheme.solution_alertmanager()
        assert _files(ops, 1, 'db1')[lab.BACKUP_FILE] == ns.backup_metric()
        assert f'backup_last_size_bytes{{db="shop"}} {data.backup_size}\n' in ns.backup_metric()
        assert _cmds(ops, 2, 'prom') == ['systemctl enable --now prometheus >/dev/null 2>&1']
        wait = ns._ops[3]['prom'][0]
        assert 'sre_prom_probe.py wait' in str(wait)

    def test_wait_has_a_long_timeout(self, lab, data):
        source = _LAB_PATH.read_text()
        assert 'self.cmd("prom", wait_cmd(checks, 150), step=3, timeout=200)' in source


class TestReferences:
    def test_references_use_the_required_names(self, lab):
        for key, reference in lab.REFERENCES.items():
            assert pm.mentions(reference, *lab.MUST_USE[key]), key
        assert sum(lab.PROMQL_POINTS.values()) == PARTS['part3']

    def test_promtool_documents(self, lab, data):
        docs = lab.promtool_documents(data)
        assert set(docs) == {"rec", "down", "queue", "watchdog"}
        for doc in docs.values():
            assert doc["rule_files"] == [lab.RULES_FILE] and doc["evaluation_interval"] == "15s"
        queue = docs["queue"]["tests"][0]["input_series"][0]["values"]
        t = data.queue_threshold
        assert queue == f"{t} {t} {t} {t} {t + 1}x20"
        assert pm.promtool_tests_cmd(docs).count("promtool test rules") == 4

    def test_probe_spec(self, lab):
        spec = lab.probe_spec()
        names = [a["labels"]["alertname"] for a in spec["alerts"]]
        assert names == ["SreProbeCritical-{nonce}"] + ["SreProbeWarning-{nonce}"] * 3
        assert spec["alerts"][0]["labels"]["instance"] == spec["alerts"][1]["labels"]["instance"]
        assert spec["ttl"] == lab.PROBE_TTL


# ---------------------------------------------------------------------------
# grading contract
# ---------------------------------------------------------------------------

class TestGrading:
    def test_nothing_runs(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        assert _totals(grade) == (0, 100)
        assert _by_part(grade) == {k: (0, v) for k, v in PARTS.items()}
        assert grade.max_step == 1

    def test_typed_answers_alone(self, lab, data, tmp_pub_dir):
        # the part 1 answers are read in the form; the expressions need Prometheus
        grade, _ = _run(lab, data, _cheat(lab, data), lambda m, c: None)
        assert _totals(grade) == (5, 100)
        assert all(_by_title(grade)[f"answer_{k}"].grade == 1
                   for k in ("type_requests", "type_queue", "type_duration", "app_version", "series_count"))

    def test_commands(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, _cheat(lab, data), lambda m, c: None)
        tests = grade.get_tests()
        assert {m for m, _ in tests} == {'prom', 'web1', 'db1', 'chat'} and {s for _, s in tests} == {1}
        for (machine, step), cmds in tests.items():
            for command, _timeout in cmds:
                assert "\n" not in command and "@@@" not in command, (machine, command[:60])
        typed = [c for c, _ in tests[('prom', 1)] if 'sre_prom_probe.py compare' in c]
        assert len(typed) == 3
        spec = {}
        for command in typed:
            spec.update({p["id"]: p for p in json.loads(
                __import__('base64').urlsafe_b64decode(command.split()[3] + '==').decode())["pairs"]})
        assert spec["q_p95"] == {"id": "q_p95", "expr": lab.REFERENCES["q_p95"], "ref": lab.REFERENCES["q_p95"]}
        assert spec["record"]["expr"] == lab.RECORD_NAME
        (probe,) = [c for c, _ in tests[('chat', 1)]]
        assert f"--am http://{data.ips.prom.ip}:9093 --need 3 --wait {lab.PROBE_WAIT}" in probe

    def test_typed_answers_are_instructor_scope(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        for element in grade.get_grade_list():
            typed = str(element.title).startswith(('answer_', 'promql_'))
            assert (element.scope == params.EXO_EVAL_SCOPE) == typed, element.title

    def test_cheat_answers_match_the_form_fields(self, lab, data, tmp_pub_dir):
        cheats = _cheat(lab, data)
        grade, _ = _run(lab, data, cheats, lambda m, c: None)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 3
        for q in forms:
            assert set(json.loads(cheats[q.question_hash])) == {f['name'] for f in q.fields}


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _run(lab, data, {}, lambda m, c: None, instructor_mode=False)
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == \
               [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 8          # the organisation + one per part
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 8 and 'informations' not in with_fragment
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        for value in (data.snmp_community, str(data.backup_size), str(data.queue_threshold), str(data.ips.web1.ip)):
            assert value in student
        # the solutions are not given to the students
        for reference in lab.REFERENCES.values():
            assert reference not in student
        assert "group_wait: 10s" not in student and "group_wait: 10s" in "\n".join(t for _, t in _all_texts(g1, ns1))

    def test_texts_are_formatted_and_render(self, lab, data, tmp_pub_dir):
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            plain = re.sub(r"```.*?```", "", re.sub(r"@@\{[^}]*\}@@", "", text), flags=re.S)
            assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*(:[^}]*)?\}(?!\})", plain), where
            assert '</' not in plain, where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        description = next(t for w, t in _all_texts(g1, ns1) if w.startswith('description:') and 'strictement' in t)
        assert '{{ $labels.instance }}' in description and '{{ $value }}' in description

    def test_course_is_numbered_and_generic(self, lab, data, tmp_pub_dir):
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        resolved, numbering = resolve_informations(ns1.informations)
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 13)]
        assert [s.number for s in numbering.sections('fr') if s.level == 2] == ['5.1', '6.1']
        informations = _text(resolved)
        assert '@@' not in informations and 'Organisation du TP' not in informations
        for value in (data.snmp_community, str(data.backup_size), str(data.ips.prom.ip), data.app_version):
            assert value not in informations
        assert '## <a id="promql"></a>6. PromQL' in informations
        assert not re.search(r"^ +```", _text(ns1.informations), re.M)      # no fence inside a list item
        for q in g1.get_questions_ordered():
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            assert '@@ref' not in description.resolve('fr')

    def test_form_fields(self, lab, data, tmp_pub_dir):
        g1, _ = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        fields = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert set(fields) == {'type_requests', 'type_queue', 'type_duration', 'app_version', 'series_count',
                               *lab.PROMQL_POINTS, 'q_bitrate'}
        assert fields['type_queue']['choices'] == ['counter', 'gauge', 'histogram', 'summary']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 9 and result.warnings == []
        assert b'instructor(' not in result.data
        stripped = tmp_path / 'prometheus_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('prometheus_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _run(module, data, {}, lambda m, c: None, instructor_mode=True)
        assert _totals(grade) == (0, 100)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|serveur|sonde|reseau|cible|regle|seuil|alerte|sauvegarde|panne)', re.I)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
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


def _json_output(result, change):
    """*result* = (output, code) of a command printing one JSON document then ===RC: the document
    changed in place by *change*, the output rebuilt."""
    out, code = result
    body, rc = pm.split_rc(out)
    doc = json.loads(body.strip().splitlines()[-1])
    change(doc)
    return json.dumps(doc) + f"\n===RC {rc}\n", code


def _when(predicate, change):
    """A mutate function changing the outputs of the commands *predicate(machine, command)* selects."""
    def mutate(machine, command, result):
        return change(result) if predicate(machine, command) else result
    return mutate


def _compare_ids(command):
    import base64
    spec = json.loads(base64.urlsafe_b64decode(command.split()[3] + "==").decode())
    return {p["id"] for p in spec["pairs"]}


INCIDENT_NODE = {'node_exporter_db1', 'textfile_value', 'textfile_type', 'node_up'}
TYPED = {'answer_type_requests', 'answer_type_queue', 'answer_type_duration', 'answer_app_version',
         'answer_series_count', 'promql_status', 'promql_errors', 'promql_p95', 'promql_top', 'promql_fill',
         'promql_rx', 'promql_maxqueue', 'promql_bitrate'}


class TestRealEvaluations:
    """What a running project really answered (z04, 2026-11-12, images 1.32 with the rebuilt
    monitoring image): tests/mock_data/prometheus/lab/*.zst."""

    def test_untouched_project(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'initial')
        assert _totals(grade) == (0, 100)

    @pytest.mark.parametrize('tag', ['solved', 'incident_queue', 'repaired'])
    def test_full_marks(self, lab, tmp_pub_dir, tag):
        grade, _ = _replay(lab, tag)
        assert _missing(grade) == [] and _totals(grade) == (100, 100)
        assert _by_part(grade) == {k: (v, v) for k, v in PARTS.items()}

    def test_node_exporter_incident(self, lab, tmp_pub_dir):
        # db1's exporter stopped: its own elements only (the rx expression still matches its
        # reference, both on web1 alone)
        grade, _ = _replay(lab, 'incident_node')
        assert set(_missing(grade)) == INCIDENT_NODE and _totals(grade) == (94, 100)

    def test_typed_answers(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', answers=False, strict=False)
        assert set(_missing(grade)) == TYPED and _totals(grade) == (70, 100)

    def test_part1_textfile(self, lab, tmp_pub_dir):
        def drop_backup(result):
            out, code = result
            return "\n".join(l for l in out.splitlines() if lab.BACKUP_METRIC not in l) + "\n", code
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'db1', drop_backup))
        assert set(_missing(grade)) == {'textfile_value', 'textfile_type'}

    def test_part2_targets_and_flags(self, lab, tmp_pub_dir):
        def slower_app(doc):
            for t in doc["data"]["activeTargets"]:
                if t["scrapePool"] == "app":
                    t["scrapeInterval"] = "15s"
                if t["scrapePool"] == "node":
                    t["labels"].pop("role", None)
        targets = _when(lambda m, c: '/api/v1/targets' in c, lambda r: _json_output(r, slower_app))
        grade, _ = _replay(lab, 'solved', mutate=targets)
        assert set(_missing(grade)) == {'app_interval', 'node_role_labels'}
        retention = _when(lambda m, c: '/api/v1/status/flags' in c, lambda r: _json_output(
            r, lambda doc: doc["data"].update({"storage.tsdb.retention.time": "15d"})))
        data_retention = _replay(lab, 'solved')[1].retention_days
        grade, _ = _replay(lab, 'solved', mutate=retention)
        assert set(_missing(grade)) == (set() if data_retention == 15 else {'retention_flag'})

    def test_part3_an_expression_with_other_series(self, lab, tmp_pub_dir):
        def by_method(doc):
            series = doc["results"]["q_p95"]["expr"]["result"]
            doc["results"]["q_p95"]["expr"]["result"] = series + [
                {"metric": {"method": "POST"}, "value": series[0]["value"]}]
        mutate = _when(lambda m, c: 'sre_prom_probe.py compare' in c and 'q_p95' in _compare_ids(c),
                       lambda r: _json_output(r, by_method))
        grade, _ = _replay(lab, 'solved', mutate=mutate)
        assert _missing(grade) == ['promql_p95']

    def test_part4_a_module_that_does_not_read_the_body(self, lab, tmp_pub_dir):
        def success(result):
            out, code = result
            return out.replace("probe_success 0", "probe_success 1"), code
        mutate = _when(lambda m, c: "9115/probe" in c and "target=http://web1:8080/ " in c, success)
        grade, _ = _replay(lab, 'solved', mutate=mutate)
        assert _missing(grade) == ['bb_module_regexp']

    def test_part5_wrong_community(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: "9116/snmp" in c,
                                                         lambda r: ("An error has occurred\n===RC 0\n", 0)))
        assert _missing(grade) == ['snmp_exporter']

    def test_part6_rules(self, lab, tmp_pub_dir):
        def failed_down(result):
            out, code = result
            head, _, tail = out.partition("===T down")
            body, _, rest = tail.partition("===RC 0")
            return head + "===T down" + body.replace("SUCCESS", "FAILED:") + "===RC 1" + rest, code
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: "promtool test rules" in c, failed_down))
        assert _missing(grade) == ['instance_down_test']

        def no_annotations(doc):
            for group in doc["data"]["groups"]:
                for rule in group["rules"]:
                    rule["annotations"] = {}
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: '/api/v1/rules' in c,
                                                         lambda r: _json_output(r, no_annotations)))
        assert set(_missing(grade)) == {'instance_down_annotation', 'queue_too_long_annotation'}

    def test_part7_routing_and_cluster(self, lab, tmp_pub_dir):
        routes = _when(lambda m, c: "amtool config routes test" in c and "severity=warning" in c,
                       lambda r: ("oncall\n===RC 0\n", 0))
        grade, _ = _replay(lab, 'solved', mutate=routes)
        assert _missing(grade) == ['am_route_warning']
        cluster = _when(lambda m, c: "sre_prom_probe.py amconfig" in c,
                        lambda r: _json_output(r, lambda doc: doc.update({"cluster": "ready"})))
        grade, _ = _replay(lab, 'solved', mutate=cluster)
        assert _missing(grade) == ['am_running_no_cluster']

    def test_part7_end_to_end(self, lab, tmp_pub_dir):
        def b_notified(doc):
            team = next(r for r in doc["records"] if r["path"] == lab.HOOK_TEAM)
            b = next(a for a in doc["am_alerts"] if a["labels"]["severity"] == "warning"
                     and a["labels"]["instance"].startswith("sre-probe-a-"))
            team["alerts"].append({"status": "firing", "labels": b["labels"]})
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'chat', lambda r: _json_output(r, b_notified)))
        assert _missing(grade) == ['e2e_inhibition']

        def split_groups(doc):
            team = next(r for r in doc["records"] if r["path"] == lab.HOOK_TEAM)
            first, second = team["alerts"][0], team["alerts"][1]
            team["alerts"] = [first]
            doc["records"].append(dict(team, alerts=[second]))
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'chat',
                                                         lambda r: _json_output(r, split_groups)))
        assert set(_missing(grade)) == {'e2e_team_grouped', 'e2e_inhibition'}

        def nothing_received(doc):
            doc["records"] = []
        grade, _ = _replay(lab, 'solved', mutate=_when(lambda m, c: m == 'chat',
                                                         lambda r: _json_output(r, nothing_received)))
        assert set(_missing(grade)) == {'e2e_oncall', 'e2e_team_grouped', 'e2e_inhibition'}

    def test_the_archive_holds_a_real_end_to_end_run(self, lab, tmp_pub_dir):
        raw = read_archive(str(_ARCHIVES / 'solved.zst'))
        (command, timeout), (out, _code) = next(iter(raw['tests'][('chat', 1)].items()))
        probe = pm.parse_webhook_probe(out)
        assert probe.ran and probe.status == 200 and 5 < probe.waited < 15
        assert {r.path for r in probe.records} == {lab.HOOK_ONCALL, lab.HOOK_TEAM}
        assert len(probe.am_alerts) == 4 and timeout >= lab.PROBE_WAIT + 20
