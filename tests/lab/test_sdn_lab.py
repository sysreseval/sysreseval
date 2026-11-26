"""Offline tests of lab/sre/_DRAFT_misc/sdn.py (Open vSwitch, OpenFlow and controllers), without Docker.

tests/mock_data/sdn/lab/ holds twelve real evaluations of the lab (s17, 2026-11-24, image sresdn/sdn:1.35 on
the published base13:1.35: Open vSwitch 3.5.0, OS-Ken 3.0.1), exported with ``sre cat --json``: a fresh
project (``lab_eval_initial``, 0) then the same project once ``solve_part1`` was applied (``lab_eval_part1``),
a project on which ``final`` was applied twice (``lab_eval_final``, 60 + 6 bonus), one fresh project per part
state applied alone (``lab_eval_part2`` ... ``lab_eval_bonus``) and five deliberate mistakes on those
projects (``lab_eval_mistake_*``: an allow-all entry of priority 1000 on sw2, the return of the web flow
removed, sw3 back in standalone mode, the controller of ctl3 stopped, an allow-all entry pushed through the
REST API on both switches of part 4).  The commands of the grader depend on the lab data only, so a replay
with the data of an evaluation must register exactly its archived commands and give its archived grades.
After a deliberate change of the grader's commands, capture them again.
"""
import ast
import copy
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import datetime
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'sdn.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'sdn' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'part1': (8, 4), 'part2': (14, 3), 'part3': (11, 5), 'part4': (12, 3), 'bonus': (6, 0)}
TOTAL = 60
FORM_ELEMENTS = {'answer_dpid1', 'answer_config', 'answer_switching', 'answer_action', 'answer_ofport',
                 'answer_priority', 'answer_tie', 'answer_miss', 'answer_install', 'answer_send', 'answer_loss',
                 'answer_dpid3', 'answer_dpid4b', 'answer_ofport4b'}
CHOICE_ELEMENTS = {'answer_config', 'answer_switching', 'answer_action', 'answer_tie', 'answer_miss',
                   'answer_install', 'answer_send', 'answer_loss'}
BONUS_ELEMENTS = {'bonus_meter', 'bonus_flow', 'bonus_rate'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('sdn_lab_under_test', _LAB_PATH)
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
    return {part: result.get(part, 0) for part in POINTS}


def _lost(grade) -> dict:
    return {str(e.title): e.max_grade - e.grade for e in grade.get_grade_list() if e.grade != e.max_grade}


def _patch_output(machine, step, needle, change, index=0):
    """A patch replacing the output of the *index*-th command of *machine* at *step* holding *needle*."""
    def patch(outputs):
        keys = sorted(k for k in outputs if k[0] == machine and k[1] == step and needle in k[2])
        assert keys, (machine, step, needle)
        output, code = outputs[keys[index]]
        outputs[keys[index]] = (change(output), code)
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

    def test_final(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6) and _lost(grade) == {}
        assert _parts(grade) == {part: sum(points) for part, points in POINTS.items()}
        assert sum(sum(p) for name, p in POINTS.items() if name != 'bonus') == TOTAL

    def test_final_without_answers(self, lab):
        grade = _replay(lab, _evaluation('final'))
        assert set(_lost(grade)) == FORM_ELEMENTS
        assert _totals(grade) == (TOTAL - sum(f for _, f in POINTS.values()), TOTAL, 6)

    @pytest.mark.parametrize('part', sorted(POINTS))
    def test_part_alone(self, lab, part):
        """Each part state applied alone on a fresh project gives its points and nothing else."""
        grade = _replay(lab, _evaluation(part), answers=f'solve_{part}')
        assert _parts(grade) == {name: (sum(POINTS[name]) if name == part else 0) for name in POINTS}

    @pytest.mark.parametrize('mistake, part, points', [
        ('acl_allow_all', 'part2', 0),            # priority=1000,actions=NORMAL: every trace forwarded
        ('acl_no_return', 'part2', 14 - 4 - 2),   # no reply of web2: acl_web, and acl_default gated on it
        ('sw3_standalone', 'part3', 11 - 2 - 2),  # sw3_secure, and sw3_ping gated on it
        ('controller_stopped', 'part3', 0),
        ('rest_allow_all', 'part4', 0),           # NORMAL at priority 1000 on both switches: no isolation
    ])
    def test_mistake(self, lab, mistake, part, points):
        grade = _replay(lab, _evaluation(f'mistake_{mistake}'))
        assert _parts(grade)[part] == points
        assert all(v == 0 for name, v in _parts(grade).items() if name != part)

    def test_scopes_and_bonus(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICE_ELEMENTS), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == BONUS_ELEMENTS

    @pytest.mark.parametrize('patch, lost', [
        # h13 answers h11: no VLAN isolation
        (lambda d: _patch_output('h11', 1, d.ip('h13'), lambda out: out.replace('0 received', '1 received')
                                 + f"\n64 bytes from {d.ip('h13')}: icmp_seq=1 ttl=64\n"), {'sw1_vlans': 4}),
        # the SSH port of web2 reachable from client2 (a trace that forwards)
        (lambda d: _patch_output('sw2', 1, f"nw_src={d.ip('client2')},nw_dst={d.ip('web2')},tcp_src=40000,tcp_dst=22",
                                 lambda out: out.replace('Datapath actions: drop', 'Datapath actions: 2')),
         {'acl_web': 4}),
        # the meter at another rate
        (lambda d: _patch_output('sw4a', 1, 'dump-meters', lambda out: re.sub(r'rate=\d+', 'rate=1000', out)),
         {'bonus_meter': 2, 'bonus_flow': 2, 'bonus_rate': 2}),
        # no meter on the flow of guest4
        (lambda d: _patch_output('sw4a', 1, 'dump-flows', lambda out: out.replace('meter:1,', '')),
         {'bonus_flow': 2, 'bonus_rate': 2}),
        # sw3 not connected
        (lambda d: _patch_output('sw3', 2, 'list Bridge', lambda out: out.replace('"is_connected"', '"was"')
                                 .replace('true,', 'false,')),
         {'sw3_connected': 3, 'sw3_secure': 2, 'sw3_table_miss': 2, 'sw3_learned': 2, 'sw3_ping': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        grade = _replay(lab, evaluation, answers='final', patch=patch(_data_of(lab, evaluation)))
        assert _lost(grade) == lost


# ---------------------------------------------------------------------------
# data, topology, states
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab):
        for _ in range(200):
            d = lab.Data.generate()
            assert lab.Data.from_dict(d.to_dict()).to_dict() == d.to_dict()
            assert d.vlan_a != d.vlan_b and all(101 <= v <= 899 and v % 100 for v in (d.vlan_a, d.vlan_b))
            assert set(d.ofports2) == set(lab.SW2_PORTS.values()) and len(set(d.ofports2.values())) == 4
            for ofports in (d.ofports2, d.ofports4a, d.ofports4b):
                assert all(5 <= p < 49 for p in ofports.values())
            assert len(set(d.ofports4a.values())) == 5 and len(set(d.ofports4b.values())) == 3
            assert d.dpid4a != d.dpid4b and all(1000 <= x < 9999 for x in (d.dpid4a, d.dpid4b))
            assert d.dpid3 >= 0x10000000 and d.dpid1 >= 0x10000000
            assert d.meter_rate % 500 == 0 and d.meter_rate not in (1000, 5000) and 2500 <= d.meter_rate <= 9500
            macs = {d.mac(h) for h in lab.HOSTS}
            assert len(macs) == len(lab.HOSTS) and all(m.startswith('02:53:44:') for m in macs)
            nets = [d.nets.lan1, d.nets.lan2, d.nets.lan3, d.nets.lan4, d.nets.lan5, d.nets.ctrl3, d.nets.ctrl4]
            assert len({str(n) for n in nets}) == 7 and all(n.is_private for n in nets)

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert len(ns._machine_specs) == 23
        no_terminal = {m for m, spec in ns._machine_specs.items() if spec.get('allow_connection') is False}
        assert no_terminal == {'ctl4', 'sw4a', 'sw4b'}
        sdn_image = {m for m, spec in ns._machine_specs.items() if 'image' in spec}
        assert sdn_image == {'sw1', 'sw2', 'sw3', 'sw4a', 'sw4b', 'ctl3', 'ctl4'}
        topology = ns._topology
        for net, machines in topology.items():
            for m, iface in machines.items():
                assert isinstance(iface, tuple) == (m in lab.HOSTS), (net, m)
        assert topology['sw2_db2']['sw2'] == 2 and topology['trunk'] == {'sw4a': 1, 'sw4b': 1}

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())

        def ops(state):
            ns._ops, ns._host_ops = {}, {}
            ns.reset_state_results()
            getattr(ns, state)()
            return {(step, m): [str(op) for op in op_list if isinstance(op, str)]
                    for step, machines in ns._ops.items() for m, op_list in machines.items()}

        initial = ops('initial')
        for sw in lab.SWITCHES:
            assert any('ovs-ctl --system-id=random start' in c for c in initial[(1, sw)]), sw
        sw2 = ' '.join(initial[(1, 'sw2')])
        assert 'fail-mode=secure' in sw2 and all(f'ofport_request={p}' in sw2 for p in data.ofports2.values())
        assert not any('add-br' in c for c in initial[(1, 'sw1')])
        assert any('os_ken.app.ofctl_rest' in c for c in initial[(1, 'ctl4')])
        assert any(f"set-controller br0 tcp:{data.ip('ctl4')}:6653" in c for c in initial[(2, 'sw4a')])
        final = ops('final')
        assert any(f'tag={data.vlan_a}' in c for c in final[(1, 'sw1')])
        assert any('replace-flows br0 /root/acl.flows' in c for c in final[(1, 'sw2')])
        assert any('os_ken.app.simple_switch_13' in c for c in final[(1, 'ctl3')])
        assert any('fail-mode=secure' in c for c in final[(2, 'sw3')])
        rest = ' '.join(final[(1, 'ops')])
        assert rest.count('flowentry/add') == 8 + 2 and 'meterentry/add' in rest and 'meterentry/modify' in rest

    def test_reference_acl(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        acl = ns.acl_flows().splitlines()
        assert acl[0] == 'priority=500,arp,actions=NORMAL' and acl[-1] == 'priority=0,actions=drop'
        assert len(acl) == 10 and all('actions=' in line for line in acl)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|partie|commutateur|controleur|locataire|rouge|bleu)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._LINKS)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields] + [c for f in fields for c in f.get('choices', [])]
        assert 'final' in names and 'solve_bonus' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []

    def test_dropdowns_never_right_first(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        right = {**{k: v for k, v in grade.get_cheat_answers('final').items()}}
        answers = {}
        for value in right.values():
            answers.update(json.loads(value))
        for q in grade.get_questions_ordered():
            for f in form_spec.form_fields(_text(q.description)):
                if f.get('choices'):
                    assert f['choices'][0] != answers[f['name']], f['name']


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _instructor_literals():
    """The literals of the tr() calls inside instructor(...)."""
    literals = []
    for node in ast.walk(ast.parse(_LAB_PATH.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'instructor':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'id', '') == 'tr' and sub.args \
                        and isinstance(sub.args[0], ast.Constant):
                    literals.append(sub.args[0].value)
    return literals


def _texts(lab, data, instructor=True):
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    course, numbering = resolve_informations(ns.informations)
    return course, numbering, grade


class TestTexts:
    def test_course(self, lab, data, tmp_pub_dir):
        course, numbering, _ = _texts(lab, data)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'why', 'architecture', 'openflow', 'ovs', 'controllers', 'beyond', 'lab']
        text = _text(course)
        assert '@@' not in text and 'Partie 1' not in text
        # no value of the instance: the course of another instance is the same text
        other = lab.Data.generate()
        other.compute_post_generate()
        other_course, _, _ = _texts(lab, other)
        assert _text(other_course) == text

    def test_translations(self, lab):
        """Every tr() text is translated in _TRANSLATIONS['en'] (the markup kept: checked for every lab of the
        directory by test_draft_misc_translations.py), the ten instructor texts among them."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == set(tr_strings) and all(english.values())
        literals = _instructor_literals()
        assert len(literals) == 10 and set(literals) <= set(english)
        assert all(english[k] != k for k in literals)
        # only three section titles and the names of the OpenFlow messages (grade element descriptions) read
        # the same in English
        assert {k for k in english if english[k] == k} == {'OpenFlow', 'Open vSwitch', 'Architecture',
                                                           'PACKET_IN', 'FLOW_MOD', 'PACKET_OUT'}
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)', fr)) == set(re.findall(r'\{(\w+)', en)), fr[:60]
        assert lab.title.resolve('en') == 'SDN: Open vSwitch, OpenFlow and controllers'
        for state in ('solve_part1', 'solve_part2', 'solve_part3', 'solve_part4', 'solve_bonus', 'final'):
            description = getattr(lab.NetScheme, state)._sre_state_description
            assert description.resolve('en') != description.resolve('fr'), state

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data)
        questions = grade.get_questions_ordered()
        assert len(questions) == 10
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 4
        for q in questions:
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert form_spec.form_fields(fr) == form_spec.form_fields(en)
            assert strip_instructor(fr) != fr, _text(q.title)
            assert unwrap_instructor(fr) != unwrap_instructor(en), _text(q.title)

    def test_no_instructor_text_for_students(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, instructor=False)
        for q in grade.get_questions_ordered():
            text = _text(q.description)
            assert '**Solution' not in text and "Pour l'enseignant" not in text and '**Réponses' not in text

    def test_rendering(self, lab, data, tmp_pub_dir):
        course, numbering, grade = _texts(lab, data)
        texts = {'informations': _text(course)}
        for index, q in enumerate(grade.get_questions_ordered()):
            texts[f'question {index}'] = _text(resolve_text(q.description, numbering))
        for name, text in texts.items():
            assert "{'" not in text and '@@ref' not in text, name
            assert not re.search(r"(?<![${%@])\{[a-z_][a-z0-9_]*\}", strip_instructor(text)), name
            for show in (False, True):
                assert '```' not in markdown_to_html(text, show_instructor=show), (name, show)

    def test_stripped_lab_file(self, lab, tmp_path):
        result = strip_tool.strip_source(_LAB_PATH.read_bytes())
        assert b'instructor(' not in result.data
        assert not result.warnings, result.warnings
        assert result.calls == 10 and result.translations == 10
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'sdn_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('sdn_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        literals = set(_instructor_literals())
        assert not set(kept) & literals
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(literals)
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6)
