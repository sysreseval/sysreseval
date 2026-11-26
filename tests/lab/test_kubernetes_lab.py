"""Offline tests of lab/sre/_DRAFT_misc/kubernetes.py (a k3s cluster), without Docker.

tests/mock_data/kubernetes/lab/ holds fifteen real evaluations of the lab (s14, 2026-11-25, image
``sretest/devops13:1.37``: k3s v1.37.2+k3s1), exported with ``sre cat --json``: a fresh project
(``lab_eval_initial``, 0), the same project once ``final`` was applied (``lab_eval_final``, 117 + 15 bonus), one
fresh project per part state (``lab_eval_solve_nodes`` ... ``lab_eval_solve_batch``), each applied alone with
its answers, and ``lab_eval_mistakes``: the ``final`` project with one mistake per part (the zone of worker2
removed, ``web`` scaled to 2, the strategy of ``api`` changed, ``MESSAGE`` given as a value, the readiness
probe of ``probe`` removed, ``front-lb`` deleted, the Redis key deleted, the egress policy of ``frontend``
deleted, the ``disktype`` label moved to worker2).  The commands of the grader depend on the lab data only,
so a replay with the data of an evaluation must register exactly its archived commands and give its
archived grades.  After a deliberate change of the grader's commands, capture them again.
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
import strip_instructor as strip_tool  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'kubernetes.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'kubernetes' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'nodes': (9, 3), 'shop': (13, 2), 'release': (11, 3), 'config': (11, 1), 'health': (11, 1),
          'expose': (15, 1), 'data': (11, 1), 'secure': (12, 2), 'ops': (10, 0),
          'rbac': (5, 0), 'hpa': (5, 0), 'batch': (5, 0)}
BONUS_PARTS = ('rbac', 'hpa', 'batch')
ALONE = {f'solve_{part}': part for part in POINTS}
FORMS = {'q_podcidr', 'q_kubelet', 'q_fqdn', 'q_kubeproxy', 'q_revision', 'q_serving', 'q_base64', 'q_liveness',
         'q_nodeport_range', 'q_storageclass', 'q_default', 'q_dns'}
CHOICES = {'q_kubelet', 'q_kubeproxy', 'q_base64', 'q_liveness', 'q_nodeport_range', 'q_default', 'q_dns'}
TOTAL = 117
BONUS = 15
FORM_POINTS = sum(f for _, f in POINTS.values())


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('kubernetes_lab_under_test', _LAB_PATH)
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
    (*answers*: the cheat answers of that state; *patch*: a function changing the {key: (output,
    code)} table first)."""
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
        assert len(keys) == 1, keys
        output, code = outputs[keys[0]]
        outputs[keys[0]] = (change(output), code)
    return patch


def _block(machine: str, needle: str, name: str, value: str):
    """A patch of a block command: the output of the block *name* replaced by *value*."""
    return _patch_output(machine, 1, needle,
                         lambda out: re.sub(rf'(=== probe {name}\n)(?:(?!=== probe ).*\n?)*',
                                            lambda m: m.group(1) + value + '\n', out))


def _snapshot(change):
    return _patch_output('control', 1, "echo '=== objects'", change)


def _text(value, lang='fr'):
    return value.resolve(lang) if hasattr(value, 'resolve') else (value.get(lang) if isinstance(value, dict) else value)


# ---------------------------------------------------------------------------
# replays of the live evaluations
# ---------------------------------------------------------------------------


class TestReplay:
    def test_initial(self, lab):
        grade = _replay(lab, _evaluation('initial'))
        assert _totals(grade) == (0, TOTAL, 0)

    def test_final(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, BONUS) and _lost(grade) == {}
        assert _parts(grade) == {part: sum(points) for part, points in POINTS.items()}
        assert sum(sum(p) for name, p in POINTS.items() if name not in BONUS_PARTS) == TOTAL
        assert sum(sum(POINTS[name]) for name in BONUS_PARTS) == BONUS

    def test_final_without_answers(self, lab):
        grade = _replay(lab, _evaluation('final'))
        assert _totals(grade) == (TOTAL - FORM_POINTS, TOTAL, BONUS) and set(_lost(grade)) == FORMS

    @pytest.mark.parametrize('state', sorted(ALONE))
    def test_part_alone(self, lab, state):
        """Each part state applied alone on a fresh project gives its points and nothing else."""
        grade = _replay(lab, _evaluation(state), answers=state)
        part = ALONE[state]
        parts = _parts(grade)
        assert parts[part] == sum(POINTS[part]), (parts, _lost(grade))
        assert all(points == 0 for name, points in parts.items() if name != part), parts

    def test_mistakes(self, lab):
        grade = _replay(lab, _evaluation('mistakes'), answers='final')
        assert _lost(grade) == MISTAKES

    def test_scopes(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICES), e.title
        assert {str(e.grade_part) for e in grade.get_grade_list() if e.bonus} == set(BONUS_PARTS)

    @pytest.mark.parametrize('patch, lost', [
        # worker2 not Ready: the service of the agent does not count either
        (lambda d: _snapshot(lambda out: re.sub(
            r'("name":"worker2".*?"type":"Ready","status":)"True"', r'\1"False"', out, count=1)),
         {'worker2_ready': 4, 'agent_enabled': 1}),
        # CoreDNS does not know web.shop
        (lambda d: _block('control', "echo '=== probe shop_dig'", 'shop_dig', ''), {'web_dns': 2}),
        # the ClusterIP always gives the same pod
        (lambda d: _block('control', "echo '=== probe shop_dig'", 'shop_curl',
                          '\n'.join(['Hostname: web-x'] * 8)), {'web_balance': 3}),
        # the secret file readable by all
        (lambda d: _block('control', "echo '=== probe shop_dig'", 'config_app',
                          f"MESSAGE={d.message}\nDB_PASSWORD={d.db_password}\nMOTD={d.motd}\nMODE=644\n"
                          f"SECRET={d.db_password}"), {'secret_file': 2}),
        # intruder reaches backend: backend is not protected, and the default deny does not work
        (lambda d: _patch_output('control', 1, 'd=$(mktemp -d)', lambda out: re.sub(
            r'(=== probe intruder_backend\n)RC=1\n.*\n', r'\1RC=0\nbackend\n', out)),
         {'default_deny': 2, 'frontend_to_backend': 3}),
        # the Ingress answers with another pod than front's
        (lambda d: _patch_output('admin', 1, f"http://{d.ingress_host}/",
                                 lambda out: re.sub(r'Hostname: \S+', 'Hostname: web-1', out)),
         {'ingress_reached': 3}),
        # admin talks to the API as another user
        (lambda d: _block('admin', "echo '=== probe whoami'", 'whoami', 'system:admin'),
         {'admin_kubeconfig': 2, 'admin_secrets_forbidden': 1}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        data = _data_of(lab, evaluation)
        grade = _replay(lab, evaluation, answers='final', patch=patch(data))
        assert _lost(grade) == lost

    @pytest.mark.parametrize('answers, lost', [
        ({'podcidr': '10.42.1.0/24 '}, {}),
        ({'podcidr': '10.42.9.0/24'}, {'q_podcidr': 2}),
        ({'revision': '3'}, {'q_revision': 2}),
        ({'fqdn': 'web.shop.svc.cluster.local.'}, {}),
        ({'fqdn': 'web.shop'}, {'q_fqdn': 1}),
    ])
    def test_answers(self, lab, answers, lost):
        evaluation = _evaluation('final')
        ns = lab.NetScheme(data=_data_of(lab, evaluation), running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        cheat = dict(grade.get_cheat_answers('final'))
        changed = False
        for key, value in list(cheat.items()):
            doc = json.loads(value)
            if set(answers) <= set(doc):
                doc.update(answers)
                cheat[key] = json.dumps(doc)
                changed = True
        assert changed
        outputs = _outputs(evaluation)
        step = 1
        while True:
            grade.reset_before_grade()
            grade.grade()
            if step == 1:
                grade._answers = cheat
            if step > grade.max_step:
                break
            for (machine, s), commands in grade.get_tests().items():
                if s == step:
                    for key in list(commands):
                        commands[key] = outputs[(machine, s, key[0], key[1])]
            step += 1
        assert _lost(grade) == lost


MISTAKES = {
    'zone_b': 1,                                    # the zone label of worker2 removed
    'web_deployment': 3, 'web_endpoints': 2,        # web scaled to 2
    'api_strategy': 2,                              # maxUnavailable 1
    'env_message': 1,                               # MESSAGE given as a value
    'readiness': 2, 'one_unready': 3,               # no readiness probe: every pod is ready
    'lb_service': 1, 'lb_reached': 3,               # front-lb deleted
    'value': 2, 'recreated': 1,                     # the Redis key deleted
    'frontend_egress': 4,                           # the egress policy of frontend deleted
    'ssd_label': 1,                                 # disktype moved to worker2 (pinned keeps its pod)
}


# ---------------------------------------------------------------------------
# data, topology, states
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        nets = [data.nets.cluster, data.nets.outside]
        assert len({str(n) for n in nets}) == 2
        for n in nets:
            assert n.subnet_of(IPv4Network('10.0.0.0/8'))
            for reserved in ('10.0.0.0/16', '10.42.0.0/16', '10.43.0.0/16'):
                assert not n.overlaps(IPv4Network(reserved)), (n, reserved)
        for m in ('control', 'worker1', 'worker2', 'gw'):
            assert getattr(data.ips, m).ip in data.nets.cluster
        assert 30100 <= data.node_port <= 32700 and 8100 <= data.lb_port <= 8999
        assert data.ingress_host.endswith('.lab.test') and data.token.startswith('sre-')

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert {m.name for m in ns.get_machines()} == {'control', 'worker1', 'worker2', 'gw', 'admin'}
        for name in ('control', 'worker1', 'worker2'):
            spec = lab.NetScheme._machine_specs[name]
            assert spec['privileged'] and spec['entrypoint'] == '/sbin/init'
            assert spec['image'].split(':')[0].endswith('/devops13')
        assert 'entrypoint' not in lab.NetScheme._machine_specs['admin']
        assert ns.get_weight() == lab.CONTROL_WEIGHT + 2 * lab.WORKER_WEIGHT + 1 + 1

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        files = {(m, op.filename): op.content for st in ops.values() for m, mops in st.items() for op in mops
                 if getattr(op, 'filename', '')}
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        # the nodes ask gw (no DNS server there: unknown names fail at once)
        resolv = {m: c for (m, f), c in files.items() if f == '/etc/resolv.conf'}
        gw = f"nameserver {data.ip('gw')}\n".encode()
        assert resolv == {'control': gw, 'worker1': gw, 'worker2': gw, 'gw': b'', 'admin': b''}
        # the server and worker1 configured and started; worker2 only prepared (part 1)
        assert ('control', '/etc/rancher/k3s/config.yaml') in files
        assert ('worker1', '/etc/rancher/k3s/config.yaml') in files
        assert ('worker2', '/etc/rancher/k3s/config.yaml') not in files
        assert ('worker2', '/etc/rancher/k3s/config.yaml.d/10-sre.yaml') in files
        assert 'systemctl enable --now k3s ' in text and 'systemctl enable --now k3s-agent' in text
        assert data.token.encode() in files[('control', '/etc/rancher/k3s/config.yaml')]
        for state in ('final', 'reset_release', 'reset_secure', *ALONE):
            ops, _ = ns.compute_state_ops(state)
            assert ops, state

    def test_given_and_reference_manifests(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert 'name: api' in ns.given_release_yaml() and lab.WHOAMI_OLD in ns.given_release_yaml()
        given = ns.given_secure_yaml()
        assert all(f'name: {n}' in given for n in ('frontend', 'backend', 'db', 'intruder', 'guest'))
        assert f'nodePort: {data.node_port}' in ns.yaml_expose() and data.ingress_host in ns.yaml_expose()
        assert data.db_password in ns.yaml_config() and data.motd in ns.yaml_config()
        assert 'defaultMode: 0400' in ns.yaml_config()
        assert 'kubernetes.io/metadata.name: kube-system' in ns.yaml_secure()
        assert all('\n' not in c for c in ns.cmds_release() + ns.cmds_nodes() + ns.cmds_data())

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|partie|etat|mot_de_passe|noeud|jeton|cle)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology) + list(lab.NetScheme._network_specs)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        names += list(lab.NAMESPACES)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields] + [c for f in fields for c in f.get('choices', [])]
        assert 'final' in names and 'reset_release' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:/-]+', n)]
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
            'orchestration', 'architecture', 'objects', 'pods', 'deployments', 'services', 'network', 'exposure',
            'config', 'health', 'storage', 'netpol', 'scheduling', 'rbac', 'scaling', 'troubleshooting']
        assert [s.tag for s in numbering.sections('fr') if s.level == 2] == [
            'k3s', 'kubectl', 'rollout', 'dns', 'statefulset']
        text = _text(course)
        assert '@@' not in text
        # no value of the instance and no summary of the questions in the course
        for value in (str(data.nets.cluster.network_address), data.ip('control'), str(data.node_port),
                      str(data.lb_port), data.ingress_host, data.message, data.db_password, data.redis_value,
                      'Partie 1'):
            assert value not in text, value

    def test_instructor_translations(self, lab):
        """Every tr() text has its English (the markup kept: checked for every lab of the directory by
        test_draft_misc_translations.py), the 21 instructor texts among them."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == set(tr_strings) and all(english.values())
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**')) for v in english.values()) == 21
        # the course headings that are names, and one list of quantities, read the same in both languages
        assert {k for k in english if english[k] == k} == {'k3s', 'kubectl', 'StatefulSet', 'NetworkPolicy',
                                                           'requests 50m / 32Mi, limits 200m / 64Mi'}
        assert lab.title.resolve('en') == "Kubernetes: deployments, services and the network of a cluster"
        for state in ('reset_release', 'reset_secure'):
            description = getattr(lab.NetScheme, state)._sre_state_description
            assert description.resolve('en').startswith('Recreates the '), state
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)\}', fr)) == set(re.findall(r'\{(\w+)\}', en)), fr[:60]

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        assert len(questions) == 21
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 8
        for q in questions:
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert form_spec.form_fields(fr) == form_spec.form_fields(en)
            if strip_instructor(fr) != fr:
                assert unwrap_instructor(fr) != unwrap_instructor(en), _text(q.title)
        for q in with_fields:
            assert strip_instructor(_text(q.description)) != _text(q.description), _text(q.title)

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
        assert result.calls == 21 and result.translations == 21
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'kubernetes_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('kubernetes_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the other texts is kept
        assert len(module._TRANSLATIONS['en']) == len(lab._TRANSLATIONS['en']) - 21
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, BONUS)
