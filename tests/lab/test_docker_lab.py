"""Offline tests of lab/sre/_DRAFT_misc/docker.py (containers with Docker), without Docker.

tests/mock_data/docker/lab/ holds twelve real evaluations of the lab (s17, 2026-11-24, image
``sredocker/docker:1.35``: docker-ce 29.10, containerd 2.4, compose 5.8), exported with
``sre cat --json``: a fresh project (``lab_eval_initial``, 0), a project once ``final`` was applied
(``lab_eval_final``, 95 + 6 bonus), one fresh project per part state (``lab_eval_solve_containers`` ...
``lab_eval_solve_routed``), each applied alone with its answers, and ``lab_eval_mistakes``: the
``final`` project with one mistake per part (``web`` without restart policy, ``app`` stopped, the
Redis key deleted, ``beta`` taken off ``backend``, ``edge`` stopped, ``hello`` removed from docker2,
the memory limit of ``sandbox`` raised, the route of ``gw`` removed).  The commands of the grader
depend on the lab data only, so a replay with the data of an evaluation must register exactly its
archived commands and give its archived grades.  After a deliberate change of the grader's
commands, capture them again.
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'docker.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'docker' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'containers': (9, 2), 'dockerfile': (15, 2), 'volumes': (8, 2), 'networks': (13, 1), 'inspect': (0, 10),
          'macvlan': (10, 2), 'registry': (11, 2), 'limits': (8, 0), 'bonus': (6, 0)}
ALONE = {'solve_containers': 'containers', 'solve_dockerfile': 'dockerfile', 'solve_volumes': 'volumes',
         'solve_networks': 'networks', 'solve_inspect': 'inspect', 'solve_macvlan': 'macvlan',
         'solve_registry': 'registry', 'solve_limits': 'limits', 'solve_routed': 'bonus'}
FORMS = {'q_logs', 'q_layer', 'q_dockerfile', 'q_volume_path', 'q_default_dns', 'q_legacy_ip', 'q_docker0_ip',
         'q_dnat', 'q_chain', 'q_process', 'q_macvlan_host', 'q_insecure'}
CHOICES = {'q_layer', 'q_dockerfile', 'q_default_dns', 'q_macvlan_host', 'q_insecure'}
TOTAL = 95
FORM_POINTS = sum(f for _, f in POINTS.values())


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('docker_lab_under_test', _LAB_PATH)
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


def _probe(name: str, value: str):
    """A patch of docker1's probe block: the output of the probe *name* replaced by *value*."""
    return _patch_output('docker1', 1, "echo '=== probe app_proc'",
                         lambda out: re.sub(rf'(=== probe {name}\n)(?:(?!=== probe ).*\n?)*',
                                            lambda m: m.group(1) + value + '\n', out))


def _snapshot(change):
    return _patch_output('docker1', 1, "echo '=== containers'", change)


# ---------------------------------------------------------------------------
# replays of the live evaluations
# ---------------------------------------------------------------------------


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
            'web_restart': 1,                                                   # --restart no
            'app_running': 1, 'app_healthy': 2, 'app_uid': 1, 'app_page': 1,    # app stopped (port still requested)
            'cache_token': 2,                                                   # DEL token (still in the AOF)
            'beta_on_backend': 1, 'beta_resolves_alpha': 2, 'beta_pings_alpha': 2,
            'edge_address': 2, 'edge_page': 2, 'edge_mac_on_lan': 2,            # edge stopped
            'hello_container': 2, 'hello_digest': 2,                            # hello removed from docker2
            'sandbox_memory': 1,
            'gw_route': 1, 'direct_page': 2,                                    # the route of gw removed
        }

    def test_scopes(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICES), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {
            'routed_network', 'direct_container', 'gw_route', 'direct_page'}

    @pytest.mark.parametrize('patch, lost', [
        # another restart policy
        (lambda d: _snapshot(lambda out: out.replace('"Name":"unless-stopped"', '"Name":"always"', 1)),
         {'web_restart': 1}),
        # the page of web without the token
        (lambda d: _patch_output('client', 1, f":{d.web_port}/", lambda out: out.replace(d.web_token, 'nginx')),
         {'web_page': 2}),
        # the embedded DNS does not know alpha
        (lambda d: _probe('beta_dns', ''), {'beta_resolves_alpha': 2}),
        # vault reaches client
        (lambda d: _probe('vault_client', 'PING_OK'), {'vault_isolated': 1}),
        # nsenter does not work: no proof of isolation
        (lambda d: _probe('vault_lo', 'PING_FAIL'), {'vault_isolated': 1}),
        # the token is not in the files of the volume
        (lambda d: _probe('cache_volume', 'MISSING'), {'cache_token_in_volume': 2}),
        # the process of app runs as root
        (lambda d: _probe('app_proc', 'Uid:\t0\t0\t0\t0\nCMDLINE python3 app.py '), {'app_uid': 1}),
        # gw sees the MAC address of docker1 for edge (a proxy ARP, not macvlan)
        (lambda d: _patch_output('gw', 2, 'ip neigh show',
                                 lambda out: re.sub(r'lladdr \S+', 'lladdr 02:00:00:00:00:01', out, count=1)),
         {'edge_mac_on_lan': 2}),
        # the registry serves another image than the one of docker2
        (lambda d: _patch_output('client', 1, '/v2/_catalog',
                                 lambda out: re.sub(r'(?i)(docker-content-digest: sha256:)[0-9a-f]+', r'\g<1>' + '0' * 64,
                                                    out)),
         {'hello_digest': 1}),
        # legacy re-created: another address, the answer of a fresh project is wrong
        (lambda d: _snapshot(lambda out: out.replace('"IPAddress":"172.17.0.2"', '"IPAddress":"172.17.0.9"')),
         {'q_legacy_ip': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        data = _data_of(lab, evaluation)
        grade = _replay(lab, evaluation, answers='final', patch=patch(data))
        assert _lost(grade) == lost

    @pytest.mark.parametrize('answers, lost', [
        ({'logs': 'docker logs -f web'}, {}),
        ({'logs': 'docker container logs web'}, {}),
        ({'logs': 'docker logs'}, {'q_logs': 1}),
        ({'after_start': 'lost'}, {'q_layer': 1}),
    ])
    def test_answers_of_part1(self, lab, answers, lost):
        evaluation = _evaluation('final')
        ns = lab.NetScheme(data=_data_of(lab, evaluation), running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        cheat = dict(grade.get_cheat_answers('final'))
        changed = False
        for key, value in list(cheat.items()):
            doc = json.loads(value)
            if 'logs' in doc:
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


# ---------------------------------------------------------------------------
# data, topology, states, reference files
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        nets = [data.nets.lan, data.nets.ext, data.nets.backend, data.nets.routed]
        assert len({str(n) for n in nets}) == 4
        for n in nets:
            assert n.subnet_of(IPv4Network('10.0.0.0/8')) and not n.subnet_of(IPv4Network('10.0.0.0/16'))
        assert data.nets.macvlan_range.subnet_of(data.nets.lan) and data.ips.edge.ip in data.nets.macvlan_range
        for key in ('gw', 'docker1', 'docker2'):
            assert getattr(data.ips, key).ip not in data.nets.macvlan_range
        assert data.ips.backend_gw.ip != data.ips.alpha.ip and data.ips.alpha.ip in data.nets.backend
        assert len({data.web_port, data.app_port, data.legacy_port}) == 3
        assert all(8100 <= p < 9000 for p in (data.web_port, data.app_port, data.legacy_port))
        assert data.sandbox_memory_mb in (64, 96, 128) and float(data.sandbox_cpus) < 1

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert {m.name for m in ns.get_machines()} == {'docker1', 'docker2', 'gw', 'client'}
        for name in ('docker1', 'docker2'):
            spec = lab.NetScheme._machine_specs[name]
            assert spec['privileged'] and spec['entrypoint'] == '/sbin/init' and spec['image'].split(':')[0].endswith('/devops13')
        assert ns.get_weight() == 100 + 45 + 1 + 1

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        for needle in ('systemctl start containerd docker', 'sre-docker-load', '/root/app/app.py',
                       f'-p {data.legacy_port}:80 nginx:alpine'):
            assert needle in text, needle
        # the Docker hosts resolve with a resolver that refuses (unknown names fail at once)
        resolv = {m: op.content for st in ops.values() for m, mops in st.items() for op in mops
                  if getattr(op, 'filename', '') == '/etc/resolv.conf'}
        assert resolv == {'docker1': b'nameserver 127.0.0.1\n', 'docker2': b'nameserver 127.0.0.1\n', 'gw': b'',
                          'client': b''}
        for state in ('final', 'restore_docker', *ALONE):
            ops, _ = ns.compute_state_ops(state)
            assert ops or state == 'solve_inspect', state
        final, _ = ns.compute_state_ops('final')
        count = sum(len(v) for st in final.values() for v in st.values())
        parts = sum(len(v) for state in ALONE for st in ns.compute_state_ops(state)[0].values() for v in st.values())
        assert count == parts
        # docker1's daemon is never restarted by the reference solution
        assert 'restart docker' not in json.dumps(final, default=str)

    def test_reference_files(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        dockerfile = ns.app_dockerfile()
        assert f'adduser -D -u {data.app_uid} app' in dockerfile and 'USER app' in dockerfile
        assert 'CMD ["python3", "app.py"]' in dockerfile and f'ENV APP_VERSION={data.app_version}' in dockerfile
        assert f'LABEL sre.token={data.hello_token}' in ns.hello_dockerfile()
        assert json.loads(ns.docker2_daemon_json()) == {'insecure-registries': ['docker1:5000']}
        assert data.web_token in ns.index_html()
        assert all('\n' not in c for state in ('containers', 'dockerfile', 'volumes', 'networks', 'macvlan',
                                               'registry_docker1', 'registry_docker2', 'limits', 'routed')
                   for c in getattr(ns, f'cmds_{state}')())

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|partie|etat|mot_de_passe|conteneur|registre)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology) + list(lab.NetScheme._network_specs)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
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
            'containers', 'kernel', 'architecture', 'images', 'dockerfile', 'lifecycle', 'ports', 'storage',
            'networks', 'underhood', 'registry', 'limits', 'cheatsheet']
        assert [s.tag for s in numbering.sections('fr') if s.level == 2] == [
            'default-bridge', 'user-networks', 'macvlan', 'routed', 'host-none']
        text = _text(course)
        assert '@@' not in text
        # no value of the instance and no summary of the questions in the course
        for value in (str(data.nets.lan.network_address), data.ip('docker1'), str(data.web_port), data.web_token,
                      data.cache_token, data.hello_token, data.app_version, 'Partie 1'):
            assert value not in text, value

    def test_translations(self, lab):
        """Every tr() text has its English (the markup kept: checked for every lab of the directory by
        test_draft_misc_translations.py), the 14 instructor texts among them."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        english = lab._TRANSLATIONS['en']
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        assert set(english) == set(tr_strings) and all(english.values())
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**')) for v in english.values()) == 14
        # the only texts that read the same in both languages
        assert {k for k in english if english[k] == k} == {"EXPOSE {port}", "ENV APP_VERSION={v}", "no-new-privileges"}
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)\}', fr)) == set(re.findall(r'\{(\w+)\}', en)), fr[:60]
        assert _text(lab.title, 'en') == "Docker: containers, images, volumes and networks"
        for state in ('restore_docker', 'solve_containers', 'solve_routed', 'final'):
            description = getattr(lab.NetScheme, state)._sre_state_description
            assert _text(description, 'en') != _text(description, 'fr'), state

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        assert len(questions) == 17
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 7
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
        assert result.calls == 17 and result.translations == 14
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'docker_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('docker_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the other texts is kept
        assert len(module._TRANSLATIONS['en']) == len(lab._TRANSLATIONS['en']) - 14
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6)
