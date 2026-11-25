"""Offline tests of lab/sre/_DRAFT_misc/docker-compose.py (Docker Compose), without Docker.

tests/mock_data/docker-compose/lab/ holds ten real evaluations of the lab (s17, 2026-11-24, image
``sredocker/docker:1.35``: docker-ce 29.10, compose 5.8), exported with ``sre cat --json``: a fresh
project (``lab_eval_initial``, 0), a project once ``final`` was applied (``lab_eval_final``, 87 + 6
bonus), one fresh project per part state (``lab_eval_solve_hello`` ... ``lab_eval_solve_remote``),
each applied alone with its answers, and ``lab_eval_mistakes``: the ``final`` project with one mistake
per part (``hello`` stopped, the ``redis`` of ``counter`` stopped, the ``app`` of ``shop`` taken off
``back``, the ``db`` of ``health`` stopped, one replica of ``scale`` stopped, the context removed).
The commands of the grader depend on the lab data only, so a replay with the data of an evaluation
must register exactly its archived commands and give its archived grades.  After a deliberate change
of the grader's commands, capture them again.
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'docker-compose.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'docker-compose' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'hello': (9, 3), 'counter': (14, 4), 'shop': (16, 2), 'config': (14, 1), 'health': (10, 2),
          'scale': (9, 3), 'bonus': (6, 0)}
ALONE = {'solve_hello': 'hello', 'solve_counter': 'counter', 'solve_shop': 'shop', 'solve_config': 'config',
         'solve_health': 'health', 'solve_scale': 'scale', 'solve_remote': 'bonus'}
FORMS = {'q_hello_network', 'q_hello_container', 'q_counter_volume', 'q_counter_down', 'q_shop_isolation',
         'q_config_override', 'q_health_wait', 'q_scale_dns', 'q_scale_command'}
CHOICES = {'q_counter_down', 'q_shop_isolation', 'q_health_wait', 'q_scale_dns'}
TOTAL = 87
FORM_POINTS = sum(f for _, f in POINTS.values())


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('docker_compose_lab_under_test', _LAB_PATH)
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


def _text(value, lang='fr'):
    return value.resolve(lang) if hasattr(value, 'resolve') else (value.get(lang) if isinstance(value, dict) else value)


# ---------------------------------------------------------------------------
# replays of the live evaluations
# ---------------------------------------------------------------------------


def _probe(name: str, value: str):
    """A patch of docker1's probe block: the output of the probe *name* replaced by *value*."""
    return _patch_output('docker1', 1, "echo '=== probe counter_redis'",
                         lambda out: re.sub(rf'(=== probe {name}\n)(?:(?!=== probe ).*\n?)*',
                                            lambda m: m.group(1) + value + '\n', out))


def _snapshot(change):
    return _patch_output('docker1', 1, "echo '=== containers'", change)


def _with_answers(lab, evaluation, field, value):
    """A replay of *evaluation* with the answers of final, *field* changed to *value*."""
    ns = lab.NetScheme(data=_data_of(lab, evaluation), running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    cheat = dict(grade.get_cheat_answers('final'))
    for key, raw in list(cheat.items()):
        doc = json.loads(raw)
        if field in doc:
            doc[field] = value
            cheat[key] = json.dumps(doc)
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
    return grade


class TestReplay:
    def test_initial(self, lab):
        grade = _replay(lab, _evaluation('initial'))
        assert _totals(grade) == (0, TOTAL, 0)

    def test_final(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6) and _lost(grade) == {}
        assert _parts(grade) == {part: sum(points) for part, points in POINTS.items()}
        assert sum(sum(p) for name, p in POINTS.items() if name != 'bonus') == TOTAL

    def test_final_without_answers(self, lab):
        grade = _replay(lab, _evaluation('final'))
        assert _totals(grade) == (TOTAL - FORM_POINTS, TOTAL, 6) and set(_lost(grade)) == FORMS

    @pytest.mark.parametrize('state', sorted(ALONE))
    def test_part_alone(self, lab, state):
        """Each part state applied alone on a fresh project gives its points and nothing else."""
        grade = _replay(lab, _evaluation(state), answers=state)
        part = ALONE[state]
        parts = _parts(grade)
        assert parts[part] == sum(POINTS[part]), parts
        assert all(points == 0 for name, points in parts.items() if name != part), parts

    def test_mistakes(self, lab):
        grade = _replay(lab, _evaluation('mistakes'), answers='final')
        assert _lost(grade) == {
            'hello_web': 2, 'hello_page': 2,                                    # hello stopped (configuration kept)
            'counter_services': 1, 'counter_appendonly': 1, 'counter_redis_private': 1,
            'counter_visits': 3,                                                # redis stopped: 503 at once
            'shop_membership': 1, 'shop_page': 3, 'shop_app_db': 1,             # app off back: db out of reach
            'health_db_check': 2, 'health_healthy': 1, 'health_project': 1,     # db stopped
            'scale_replicas': 3, 'scale_no_fixed_port': 1, 'scale_balanced': 2,  # two replicas left
            'remote_context': 2,                                                # the project keeps running on docker2
        }

    def test_scopes(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICES), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {
            'remote_context', 'remote_running', 'remote_from_docker1', 'remote_page'}

    @pytest.mark.parametrize('patch, lost', [
        # the counter does not move: the second answer repeats the first visit
        (lambda d: _patch_output('client', 1, f":{d.counter_port}/",
                                 lambda out: re.sub(r'"visits": (\d+)', '"visits": 1', out)),
         {'counter_visits': 2}),
        # proxy reaches db
        (lambda d: _probe('shop_proxy_db', 'PING_OK'), {'shop_proxy_isolated': 1}),
        # a wrong secret
        (lambda d: _probe('config_secret_app', 'not-the-password'), {'config_secret': 2}),
        # Redis without a password
        (lambda d: _probe('config_noauth', '+PONG'), {'config_requirepass': 2}),
        # the password in the environment of app
        (lambda d: _snapshot(lambda out: out.replace('"REDIS_PASSWORD_FILE=/run/secrets/redis_password"',
                                                     f'"REDIS_PASSWORD={d.redis_password}"')),
         {'config_no_leak': 2}),
        # app does not wait for db to be healthy
        (lambda d: _snapshot(lambda out: out.replace('db:service_healthy:', 'db:service_started:')),
         {'health_depends_on': 2}),
        # nginx resolved app before the replicas: one host name only
        (lambda d: _patch_output('client', 1, '?i=[1-6]',
                                 lambda out: re.sub(r'"hostname": "[0-9a-f]+"', '"hostname": "one"', out)),
         {'scale_balanced': 4}),
        # a context over TCP
        (lambda d: _probe('context', '{"Host":"tcp://docker2:2375","SkipTLSVerify":false}'), {'remote_context': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        data = _data_of(lab, evaluation)
        grade = _replay(lab, evaluation, answers='final', patch=patch(data))
        assert _lost(grade) == lost

    @pytest.mark.parametrize('value, lost', [
        ('docker compose up -d --scale app=5', {}),
        ('docker compose up --scale app=5 -d', {}),
        ('docker compose up --scale app=5', {'q_scale_command': 1}),
        ('docker compose scale app=5', {'q_scale_command': 1}),
    ])
    def test_scale_command(self, lab, value, lost):
        assert _lost(_with_answers(lab, _evaluation('final'), 'scale', value)) == lost


# ---------------------------------------------------------------------------
# data, topology, states, reference files
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        nets = [data.nets.lan, data.nets.ext, data.nets.front, data.nets.back]
        assert len({str(n) for n in nets}) == 4
        for n in nets:
            assert n.subnet_of(IPv4Network('10.0.0.0/8')) and not n.subnet_of(IPv4Network('10.0.0.0/16'))
        assert data.ips.db.ip in data.nets.back
        ports = [data.hello_port, data.counter_port, data.shop_port, data.config_port, data.scale_port, data.remote_port]
        assert len(set(ports)) == 6 and all(8100 <= p < 9000 for p in ports)
        assert data.ssh_private_key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----')
        assert data.ssh_public_key.startswith('ssh-ed25519 ') and data.config_color in lab.COLORS

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert {m.name for m in ns.get_machines()} == {'docker1', 'docker2', 'gw', 'client'}
        for name in ('docker1', 'docker2'):
            spec = lab.NetScheme._machine_specs[name]
            assert spec['privileged'] and spec['entrypoint'] == '/sbin/init' and spec['image'].split(':')[0].endswith('/docker13')
        assert ns.get_weight() == 125 + 50 + 1 + 1

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        for needle in ('systemctl start containerd docker', 'sre-docker-load', 'systemctl start ssh',
                       '/root/compose/remote/compose.yaml', '/root/.ssh/authorized_keys',
                       *(f'/root/compose/{p}/app/app.py' for p in lab.APP_PROJECTS)):
            assert needle in text, needle
        resolv = {m: op.content for st in ops.values() for m, mops in st.items() for op in mops
                  if getattr(op, 'filename', '') == '/etc/resolv.conf'}
        assert resolv == {'docker1': b'nameserver 127.0.0.1\n', 'docker2': b'nameserver 127.0.0.1\n', 'gw': b'',
                          'client': b''}
        for state in ('final', 'restore_docker', *ALONE):
            ops, _ = ns.compute_state_ops(state)
            assert ops, state
        final, _ = ns.compute_state_ops('final')
        count = sum(len(v) for st in final.values() for v in st.values())
        parts = sum(len(v) for state in ALONE for st in ns.compute_state_ops(state)[0].values() for v in st.values())
        assert count == parts

    def test_reference_files(self, lab, data):
        yaml = pytest.importorskip('yaml')
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for name in ('hello_compose', 'counter_compose', 'shop_compose', 'config_compose', 'config_override',
                     'health_compose', 'scale_compose', 'remote_compose'):
            doc = yaml.safe_load(getattr(ns, name)())
            assert 'services' in doc, name
        shop = yaml.safe_load(ns.shop_compose())
        assert shop['networks']['back']['internal'] is True
        assert shop['services']['db']['networks']['back']['ipv4_address'] == data.ip('db')
        config = yaml.safe_load(ns.config_compose())
        assert data.redis_password not in ns.config_compose() and 'ports' not in config['services']['app']
        assert config['services']['redis']['command'][2].startswith('exec redis-server --requirepass "$$(cat')
        assert yaml.safe_load(ns.config_override())['services']['app']['ports'] == ['${APP_PORT}:8080']
        assert yaml.safe_load(ns.health_compose())['services']['app']['depends_on'] == {
            'db': {'condition': 'service_healthy'}}
        assert yaml.safe_load(ns.scale_compose())['services']['app']['deploy'] == {'replicas': lab.REPLICAS}
        assert data.remote_token in ns.remote_compose() and './' not in ns.remote_compose()
        assert 'proxy_pass http://app:8080;' in ns.shop_nginx() and 'server app:8080;' in ns.scale_nginx()

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|partie|etat|mot_de_passe|conteneur|registre)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology) + list(lab.NetScheme._network_specs)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        names += list(lab.PROJECTS)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields] + [c for f in fields for c in f.get('choices', [])]
        assert 'final' in names and 'restore_docker' in names
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
            'why', 'file', 'project', 'commands', 'build', 'networks', 'volumes', 'variables', 'secrets', 'override',
            'health', 'scale', 'contexts', 'cheatsheet']
        text = _text(course)
        assert '@@' not in text
        for value in (str(data.nets.lan.network_address), data.ip('docker1'), str(data.hello_port), data.hello_token,
                      data.redis_password, data.config_version, data.config_color + '\n', 'Partie 1'):
            assert value not in text, value

    def test_instructor_translations(self, lab):
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        english = lab._TRANSLATIONS['en']
        assert set(english) <= set(tr_strings) and None not in english.values() and len(english) == 14
        assert all(english[k] != k for k in english)
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)\}', fr)) == set(re.findall(r'\{(\w+)\}', en)), fr[:60]

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        assert len(questions) == 14
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 6
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
        assert not result.warnings, result.warnings
        assert result.calls == 14 and result.translations == 14
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'docker_compose_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('docker_compose_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6)
