"""Offline tests of lab/sre/_DRAFT_misc/sdwan.py (SD-WAN: tunnels, control plane, application-aware routing,
SLA), without Docker.

tests/mock_data/sdwan/lab/ holds fourteen real evaluations of the lab (s17, 2026-11-24, routing-frr:1.35 and
base13:1.35: FRR 10.3, WireGuard, nftables 1.1.3), exported with ``sre cat --json``: a fresh project
(``lab_eval_initial``, 0), a project once ``final`` was applied (``lab_eval_final``, 89 + 6 bonus), one fresh
project per part state applied alone (``lab_eval_part1`` ... ``lab_eval_part6``; ``lab_eval_bonus``: the
bonus state, which also applies part 2), mistakes on the final project (``lab_eval_mistakes``: the ERP rule
of edge3 deleted, the NAT of edge4 deleted, the SLA script of edge5 killed, the local-preference of edge2
removed; then ``lab_eval_mistake_policy_invalid``: a policy that is not JSON written on orch, the agent keeps
the previous one) and on the projects of a part alone (``lab_eval_trick_voice_always_inet``: no script on
edge5, voice routed over the Internet tunnel for good; ``lab_eval_trick_policy_voice_inet``: a policy whose
voice may only use the Internet tunnel; ``lab_eval_mistake_no_prepend``: edge2 without its AS-path prepend).
The commands of the grader depend on the lab data only, so a replay with the data of an evaluation must
register exactly its archived commands and give its archived grades.  After a deliberate change of the
grader's commands, capture them again.
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
import sdwan_agent  # noqa: E402
import wireguard  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'sdwan.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'sdwan' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'part1': (10, 4), 'part2': (12, 3), 'part3': (16, 2), 'part4': (10, 2), 'part5': (12, 2),
          'part6': (14, 2), 'bonus': (6, 0)}
TOTAL = 89
CHOICE_ELEMENTS = {'answer_keepalive', 'answer_known', 'answer_rfc8212', 'answer_local', 'answer_remote',
                   'answer_why', 'answer_nat', 'answer_brownout', 'answer_hysteresis', 'answer_roles',
                   'answer_jitter'}
FORM_ELEMENTS = CHOICE_ELEMENTS | {'answer_overhead', 'answer_dscp', 'answer_tos'}
BONUS_ELEMENTS = {'bonus_bfd', 'bonus_failover'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('sdwan_lab_under_test', _LAB_PATH)
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


def _patch_output(machine, step, needle, change):
    """A patch replacing the output of the one command of *machine* at *step* holding *needle*."""
    def patch(outputs):
        keys = [k for k in outputs if k[0] == machine and k[1] == step and needle in k[2]]
        assert len(keys) == 1, (machine, step, needle, len(keys))
        output, code = outputs[keys[0]]
        outputs[keys[0]] = (change(output), code)
    return patch


def _text(value, lang='fr'):
    return value.resolve(lang) if hasattr(value, 'resolve') else (value.get(lang) if isinstance(value, dict) else value)


# ---------------------------------------------------------------------------
# replays of the live evaluations
# ---------------------------------------------------------------------------

MISTAKES_LOST = {
    'edge2_prefers_mpls': 2,   # no local-preference: still MPLS, but by a tie-break, which is no preference
    'edge3_erp': 4,            # the ERP rule deleted
    'edge4_saas_direct': 5,    # no NAT: the SaaS answers to a private address
    'edge4_backhaul': 5,       # gated on the SaaS element
    'edge5_leaves_mpls': 8,    # the script killed: voice stays on MPLS
    'edge5_comes_back': 4,
}


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

    @pytest.mark.parametrize('part', [p for p in POINTS if p != 'bonus'])
    def test_part_alone(self, lab, part):
        """Each part state applied alone on a fresh project gives its points and nothing else."""
        grade = _replay(lab, _evaluation(part), answers=f'solve_{part}')
        assert _parts(grade) == {name: (sum(POINTS[name]) if name == part else 0) for name in POINTS}

    def test_bonus_with_part2(self, lab):
        grade = _replay(lab, _evaluation('bonus'), answers='solve_bonus')
        assert _parts(grade) == {name: (sum(POINTS[name]) if name in ('part2', 'bonus') else 0) for name in POINTS}

    @pytest.mark.parametrize('name', ['mistakes', 'mistake_policy_invalid'])
    def test_mistakes_on_final(self, lab, name):
        grade = _replay(lab, _evaluation(name), answers='final')
        assert _lost(grade) == MISTAKES_LOST

    @pytest.mark.parametrize('name, part, points', [
        ('trick_voice_always_inet', 'part5', 2),     # the forms only: voice never on MPLS when healthy
        ('trick_policy_voice_inet', 'part6', 3 + 2),  # a policy is applied, and the forms
        ('mistake_no_prepend', 'part2', 15 - 2),      # the hub's choice of MPLS is a tie-break
    ])
    def test_tricks(self, lab, name, part, points):
        grade = _replay(lab, _evaluation(name), answers=f'solve_{part}')
        assert _parts(grade)[part] == points
        assert all(v == 0 for p, v in _parts(grade).items() if p != part)

    def test_scopes_and_bonus(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICE_ELEMENTS), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == BONUS_ELEMENTS

    @pytest.mark.parametrize('patch, lost', [
        # the ERP probes of pc3 not counted on MPLS at step 3
        (lambda d: _patch_output('hub', 3, 'sre_count', lambda out: re.sub(r'pc3\|mpls\|erp \d+', 'pc3|mpls|erp 0', out)),
         {'edge3_erp': 4}),
        # the agent without policy
        (lambda d: _patch_output('edge6', 1, 'sdwan-agent status', lambda out: re.sub(r'"policy": \{[^}]*\}',
                                                                                     '"policy": null', out)),
         {'edge6_policy': 3}),
        # the SaaS sees the hub: backhauled
        (lambda d: _patch_output('pc4', 1, d.ip('saas'), lambda out: out.replace(d.ip('edge4_inet'), d.ip('hub_inet'))),
         {'edge4_saas_direct': 5, 'edge4_backhaul': 5}),
        # 30 pings lost during the cut
        (lambda d: _patch_output('pc2', 3, 'ping', lambda out: re.sub(r'(\d+) received', lambda m: f'{int(m.group(1)) - 30} received', out)),
         {'bonus_failover': 4}),
        # edge2 goes to the data centre over the Internet tunnel
        (lambda d: _patch_output('edge2', 1, 'route get', lambda out: out.replace('wg-mpls', 'wg-inet')),
         {'edge2_prefers_mpls': 2}),
        # the BFD session of the MPLS tunnel down
        (lambda d: _patch_output('hub', 1, 'show bfd peers', lambda out: json.dumps(
            [dict(p, status='down') if p.get('peer') == d.ip('edge2_ov_mpls') else p for p in json.loads(out)])),
         {'bonus_bfd': 2, 'bonus_failover': 4}),
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
            assert 64600 <= d.edge2_as <= 64999 and d.edge2_as != lab.HUB_AS
            keys = [d.hub_mpls_key, d.hub_inet_key] + list(d.edge_keys.values())
            assert len(set(keys)) == 8 and all(wireguard.is_wg_key(k) for k in keys)
            assert set(d.edge_keys) == set(lab.EDGES)
            private = [d.nets.dc_lan, d.nets.ov_mpls, d.nets.ov_inet] + [getattr(d.nets, f'lan{i}') for i in lab.SITES]
            assert all(n.is_private and n.prefixlen == 24 for n in private) and len({str(n) for n in private}) == 9
            mpls = [d.nets.mpls_hub] + [getattr(d.nets, f'mpls{i}') for i in lab.SITES]
            assert all(n.subnet_of(d.nets.mpls_space) for n in mpls) and len({str(n) for n in mpls}) == 7
            assert d.nets.mpls_space.subnet_of(IPv4Network('100.64.0.0/10'))
            public = [d.nets.inet_hub, d.nets.public, d.nets.www, d.nets.saas] + \
                [getattr(d.nets, f'inet{i}') for i in lab.SITES]
            assert all(n.subnet_of(IPv4Network('198.18.0.0/15')) for n in public) and len({str(n) for n in public}) == 10
            assert d.ip('hub_ov_mpls').endswith('.1') and d.ip('edge4_ov_inet').endswith('.14')

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert len(ns._machine_specs) == 18 and len(ns._network_specs) == 22
        no_terminal = {m for m, spec in ns._machine_specs.items() if spec.get('allow_connection') is False}
        assert no_terminal == {'mpls', 'inet', 'hub', 'dc', 'cloud'}
        frr = {m for m, spec in ns._machine_specs.items() if 'image' in spec}
        assert frr == {'hub'} | set(lab.EDGES)
        assert set(ns._machine_specs).isdisjoint(ns._network_specs)   # Kathara refuses a shared name
        assert ns._topology['mpls5'] == {'mpls': 5, 'edge5': 1} and ns._topology['inet2'] == {'inet': 2, 'edge2': 2}

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())

        def ops(state):
            ns._ops, ns._host_ops = {}, {}
            ns.reset_state_results()
            getattr(ns, state)()
            cmds, files = {}, {}
            for step, machines in ns._ops.items():
                for m, op_list in machines.items():
                    for op in op_list:
                        if isinstance(op, str):
                            cmds.setdefault(m, []).append(op)
                        else:
                            files.setdefault(m, {})[op.filename] = (op.content.decode()
                                                                    if isinstance(op.content, bytes) else op.content)
            return cmds, files

        cmds, files = ops('initial')
        hub_mpls = files['hub']['/etc/wireguard/wg-mpls.conf']
        assert hub_mpls.count('[Peer]') == 6 and f"ListenPort = {lab.WG_PORT_MPLS}" in hub_mpls
        assert all(data.pub(e) in hub_mpls for e in lab.EDGES)
        frr = files['hub']['/etc/frr/frr.conf']
        assert 'listen range' not in frr and ' bfd\n' not in frr.split('\nbfd\n')[0]
        assert f"peer {data.ip('edge2_ov_mpls')} local-address {data.ip('hub_ov_mpls')} interface wg-mpls" in frr
        assert f"neighbor EDGE2 remote-as {data.edge2_as}" in frr
        assert any('ip rule add fwmark 1 lookup 101' in c for c in cmds['hub'])
        assert '/etc/wireguard/wg-mpls.conf' not in files['edge1'] and '/etc/wireguard/private.key' in files['edge1']
        assert 'PersistentKeepalive = 25' in files['edge3']['/etc/wireguard/wg-inet.conf']
        assert any('replace default dev wg-mpls' in c for c in cmds['edge4'])
        assert any(f'lookup {lab.VOICE_TABLE}' in c for c in cmds['edge5'])
        assert f"controller=http://{data.ip('orch')}" in files['edge6']['/etc/sdwan-agent.conf']
        assert any('http.server 80' in c for c in cmds['orch'])
        cmds, files = ops('final')
        assert files['edge1']['/etc/wireguard/wg-mpls.conf'] == ns.edge_wg_conf('edge1', 'mpls')
        assert any('route-map MPLS-IN permit 10' in c and 'as-path prepend' in c for c in cmds['edge2'])
        assert any(' bfd' in c for c in cmds['edge2'])
        assert 'tcp dport 8443 meta mark set 0x10' in files['edge3']['/etc/nftables-sdwan.nft']
        assert files['edge5'][lab.SLA_SCRIPT] == ns.sla_script()
        policy, errors = sdwan_agent.validate_policy(json.loads(files['orch'][f'{lab.POLICY_DIR}/edge6.json']))
        assert errors == [] and [a['name'] for a in policy['applications']] == ['voice', 'bulk']

    def test_reference_policy_and_example(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        example, errors = sdwan_agent.validate_policy(json.loads(ns.policy_example()))
        assert errors == [] and example['applications'] == [] and set(example['paths']) == {'mpls', 'inet'}

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|partie|agence|siege|tunnel_|voix|politique)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._network_specs)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields] + [c for f in fields for c in f.get('choices', [])]
        assert 'final' in names and 'mpls_degraded' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []

    def test_dropdowns_never_right_first(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        answers = {}
        for value in grade.get_cheat_answers('final').values():
            answers.update(json.loads(value))
        for q in grade.get_questions_ordered():
            for f in form_spec.form_fields(_text(q.description)):
                if f.get('choices'):
                    assert f['choices'][0] != answers[f['name']], f['name']


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


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
            'why', 'principles', 'overlay', 'control', 'apps', 'sla', 'dia', 'agent', 'lab']
        text = _text(course)
        assert '@@' not in text and 'Partie 1' not in text
        other = lab.Data.generate()
        other.compute_post_generate()
        other_course, _, _ = _texts(lab, other)
        assert _text(other_course) == text

    def test_course_policy_example_is_valid(self, lab, data, tmp_pub_dir):
        course, _, _ = _texts(lab, data)
        block = re.search(r'```\n(\{\n  "version".*?\n\})\n```', _text(course), re.S).group(1)
        policy, errors = sdwan_agent.validate_policy(json.loads(block))
        assert errors == [] and policy['applications'][0]['match'] == {'dscp': 34}

    def test_instructor_translations(self, lab):
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        english = lab._TRANSLATIONS['en']
        assert set(english) <= set(tr_strings) and None not in english.values() and len(english) == 14
        assert all(english[k] != k for k in english)
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)', fr)) == set(re.findall(r'\{(\w+)', en)), fr[:60]

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data)
        questions = grade.get_questions_ordered()
        assert len(questions) == 14
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 6
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
            assert not re.search(r"(?<![${%@\\(])\{[a-z_][a-z0-9_]*\}", strip_instructor(text)), name
            for show in (False, True):
                assert '```' not in markdown_to_html(text, show_instructor=show), (name, show)

    def test_stripped_lab_file(self, lab, tmp_path):
        result = strip_tool.strip_source(_LAB_PATH.read_bytes())
        assert b'instructor(' not in result.data
        assert not result.warnings, result.warnings
        assert result.calls == 14 and result.translations == 14
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'sdwan_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('sdwan_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6)
