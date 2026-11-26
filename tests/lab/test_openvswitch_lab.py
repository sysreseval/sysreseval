"""Offline tests of lab/sre/_DRAFT_misc/openvswitch.py (Open vSwitch without controller), without Docker.

tests/mock_data/openvswitch/lab/ holds real evaluations of the lab (s17, 2026-11-25, the published images
sysreseval/netdev13:1.36 and base13:1.36: Open vSwitch 3.5.0), exported with ``sre cat --json``: a project on
which ``final`` was applied twice (``lab_eval_final``, 75 + 6 bonus), a fresh project (``lab_eval_initial``,
0) then the same project once ``solve_part1`` was applied (``lab_eval_part1``), one fresh project per other
part state applied alone (``lab_eval_part2`` ... ``lab_eval_bonus``) and one deliberate mistake on each of
those projects (``lab_eval_mistake_*``: the trunk carrying every VLAN, a balance-slb bond, the MTU of hv3b
back at 1500, a stateless firewall on fw4, a mirror of what h5a sends only, the queue flow matching h5a).
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

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'openvswitch.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'openvswitch' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'part1': (14, 4), 'part2': (9, 4), 'part3': (14, 4), 'part4': (12, 3), 'part5': (9, 2), 'bonus': (6, 0)}
TOTAL = 75
CHOICE_ELEMENTS = {'answer_empty', 'answer_both', 'answer_type', 'answer_lacp_mode', 'answer_first',
                   'answer_flag', 'answer_policing_unit', 'answer_qos_unit'}
FORM_ELEMENTS = CHOICE_ELEMENTS | {'answer_local', 'answer_partner', 'answer_ofports', 'answer_vxlan_port',
                                   'answer_geneve_port', 'answer_overhead', 'answer_device', 'answer_commit'}
BONUS_ELEMENTS = {'bonus_qos', 'bonus_flow', 'bonus_rate'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('openvswitch_lab_under_test', _LAB_PATH)
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

    @pytest.mark.parametrize('mistake, part, lost', [
        ('trunk_all', 'part1', {'p1_trunk': 2}),               # trunks cleared: every VLAN crosses
        ('bond_slb', 'part2', {'p2_mode': 1}),                 # LACP still negotiated
        ('mtu_1500', 'part3', {'p3_mtu': 2}),                  # blue3b -> blue3a leaves hv3b at 1500
        ('stateless', 'part4', {'p4_stateful': 2, 'p4_conntrack': 2}),  # tp_src=80 lets the SYN+ACK in
        ('mirror_src_only', 'part5', {'p5_mirror': 2}),        # the replies of h5a are still mirrored
        ('queue_h5a', 'bonus', {'bonus_flow': 2, 'bonus_rate': 2}),
    ])
    def test_mistake(self, lab, mistake, part, lost):
        grade = _replay(lab, _evaluation(f'mistake_{mistake}'))
        assert {k: v for k, v in _lost(grade).items() if k not in FORM_ELEMENTS and k.startswith(_PREFIX[part])} == lost
        assert _parts(grade)[part] == POINTS[part][0] - sum(lost.values())
        assert all(v == 0 for name, v in _parts(grade).items() if name != part)

    def test_scopes_and_bonus(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICE_ELEMENTS), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == BONUS_ELEMENTS

    @pytest.mark.parametrize('patch, lost', [
        # one LACP member expired
        (lambda d: _patch_output('hv2', 1, 'lacp/show', lambda out: out.replace('current attached', 'expired attached', 1)),
         {'p2_lacp': 3}),
        # the VXLAN key of hv3a wrong
        (lambda d: _patch_output('hv3a', 1, 'list Interface', lambda out: out.replace(f'"key","{d.vni_red}"', '"key","1"')),
         {'p3_tunnels_a': 2}),
        # a red machine answers a blue one
        (lambda d: _patch_output('red3a', 1, f"ping -c 1 -w 2 {d.ip('blue3a')}",
                                 lambda out: out + f"\n64 bytes from {d.ip('blue3a')}: icmp_seq=1 ttl=64\n"),
         {'p3_isolation': 2}),
        # no committed connection
        (lambda d: _patch_output('fw4', 2, 'dump-conntrack', lambda out: ''), {'p4_conntrack': 2}),
        # the SYN+ACK trace forwarded
        (lambda d: _patch_output('fw4', 1, 'tcp_flags=0x012', lambda out: out.replace('Datapath actions: drop', 'Datapath actions: 1')),
         {'p4_stateful': 2}),
        # nothing seen on ids5
        (lambda d: _patch_output('ids5', 3, 'tcpdump -n -r', lambda out: ''), {'p5_capture': 3}),
        # the policing at another rate
        (lambda d: _patch_output('sw5', 1, 'list Interface',
                                 lambda out: _set_ovs_column(out, 'Interface', 'eth3', 'ingress_policing_rate', 1000)),
         {'p5_policing': 2, 'p5_rate': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        grade = _replay(lab, evaluation, answers='final', patch=patch(_data_of(lab, evaluation)))
        assert _lost(grade) == lost


def _set_ovs_column(output, table, name, column, value):
    """The output of ``sdn.ovs_state_cmd(OVS_TABLES_FULL)`` with *column* of the row *name* of *table* changed."""
    tables = ('Bridge', 'Port', 'Interface', 'Controller', 'Mirror', 'QoS', 'Queue')
    chunks = output.split('==SRE-SDN==')
    index = tables.index(table)
    doc = json.loads(chunks[index])
    for row in doc['data']:
        cells = dict(zip(doc['headings'], row))
        if cells['name'] == name:
            row[doc['headings'].index(column)] = value
    chunks[index] = '\n' + json.dumps(doc) + '\n'
    return '==SRE-SDN=='.join(chunks)


_PREFIX = {'part1': 'p1_', 'part2': 'p2_', 'part3': 'p3_', 'part4': 'p4_', 'part5': 'p5_', 'bonus': 'bonus_'}


# ---------------------------------------------------------------------------
# data, topology, states
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab):
        for _ in range(200):
            d = lab.Data.generate()
            assert lab.Data.from_dict(d.to_dict()).to_dict() == d.to_dict()
            vlans = [d.vlan_users, d.vlan_servers, d.tag_red_a, d.tag_blue_a, d.tag_red_b, d.tag_blue_b]
            assert len(set(vlans)) == 6 and all(101 <= v <= 899 and v % 100 for v in vlans)
            assert d.vni_red != d.vni_blue and all(1001 <= v < 99999 and v % 100 for v in (d.vni_red, d.vni_blue))
            assert re.fullmatch(r'02:1a(:[0-9a-f]{2}){4}', d.lacp_sysid)
            for ofports, ports in ((d.ofports4, lab.SW4_PORTS), (d.ofports5, lab.SW5_PORTS)):
                assert set(ofports) == set(ports.values()) and len(set(ofports.values())) == len(ports)
                assert all(5 <= p < 49 for p in ofports.values())
            assert d.police_rate % 500 == 0 and d.police_rate != 5000 and 2000 <= d.police_rate <= 9500
            assert d.queue_rate % 500 == 0 and d.queue_rate not in (5000, d.police_rate) and 2000 <= d.queue_rate <= 8000
            macs = {d.mac(h) for h in lab.HOSTS}
            assert len(macs) == len(lab.HOSTS) and all(m.startswith('02:4f:56:') for m in macs)
            nets = [d.nets.users1, d.nets.servers1, d.nets.lan2, d.nets.under3a, d.nets.under3b, d.nets.tenant3,
                    d.nets.lan4, d.nets.lan5]
            assert len({str(n) for n in nets}) == 8 and all(n.is_private for n in nets)

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert len(ns._machine_specs) == 26 and ns.get_weight() == 26
        no_terminal = {m for m, spec in ns._machine_specs.items() if spec.get('allow_connection') is False}
        assert no_terminal == {'tor2'}
        ovs_image = {m for m, spec in ns._machine_specs.items() if 'image' in spec}
        assert ovs_image == set(lab.SWITCHES)
        topology = ns._topology
        for net, machines in topology.items():
            for m, iface in machines.items():
                assert isinstance(iface, tuple) == (m in lab.HOSTS), (net, m)
        assert topology['trunk1'] == {'sw1a': 0, 'sw1b': 0} and topology['under3b'] == {'hv3b': 0, 'core3': 1}

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
        tor2 = ' '.join(initial[(1, 'tor2')])
        assert 'add-bond br0 bond0 eth0 eth1' in tor2 and f'other_config:lacp-system-id={data.lacp_sysid}' in tor2
        assert 'bond_mode=balance-tcp lacp=active' in tor2 and 'lacp-time=fast' in tor2
        for sw in ('sw1a', 'sw1b', 'hv3a', 'hv3b'):
            assert not any('add-br' in c for c in initial[(1, sw)]), sw
        assert any(f'ofport_request={p}' in c for p in data.ofports4.values() for c in initial[(1, 'fw4')])
        assert any('mtu 9000' in c for c in initial[(1, 'core3')])
        final = ops('final')
        assert any(f"trunks={','.join(str(v) for v in sorted((data.vlan_users, data.vlan_servers)))}" in c
                   for c in final[(1, 'sw1a')])
        assert any('type=internal' in c and 'gw-users' in c for c in final[(1, 'sw1a')])
        assert not any('gw-users' in c for c in final[(1, 'sw1b')])
        assert any(f'options:key={data.vni_red}' in c and f'tag={data.tag_red_b}' in c for c in final[(1, 'hv3b')])
        assert any('type=geneve' in c for c in final[(1, 'hv3a')])
        assert any('replace-flows br0 /root/fw.flows' in c for c in final[(1, 'fw4')])
        sw5 = ' '.join(final[(1, 'sw5')])
        assert 'create mirror name=span' in sw5 and f'ingress_policing_rate={data.police_rate}' in sw5
        assert f'other_config:max-rate={data.queue_rate * 1000}' in sw5 and 'set_queue:1,NORMAL' in sw5

    def test_reference_pipeline(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        flows = ns.fw_flows().splitlines()
        assert flows[0] == 'table=0,priority=200,arp,actions=NORMAL' and flows[-1] == 'table=1,priority=0,actions=drop'
        assert sum('ct(commit)' in f for f in flows) == 2 and sum('ct(table=1)' in f for f in flows) == 1

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|partie|commutateur|locataire|rouge|bleu|hyperviseur)', re.I)
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
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', n)]
        assert bad == []

    def test_dropdowns_never_right_first(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        answers = {}
        for value in grade.get_cheat_answers('final').values():
            answers.update(json.loads(value))
        choices = 0
        for q in grade.get_questions_ordered():
            for f in form_spec.form_fields(_text(q.description)):
                if f.get('choices'):
                    choices += 1
                    assert f['choices'][0] != answers[f['name']], f['name']
        assert choices == len(CHOICE_ELEMENTS)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _instructor_literals():
    """The French literals of the tr() calls inside instructor()."""
    ast = check_sre_translations.ast
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
            'why', 'arch', 'vlan', 'bond', 'tunnels', 'pipeline', 'conntrack', 'mirror', 'qos', 'tools', 'lab']
        text = _text(course)
        assert '@@' not in text and 'Partie 1' not in text
        # no value of the instance: the course of another instance is the same text
        other = lab.Data.generate()
        other.compute_post_generate()
        other_course, _, _ = _texts(lab, other)
        assert _text(other_course) == text

    def test_every_reference_exists(self, lab, data, tmp_pub_dir):
        course, numbering, grade = _texts(lab, data)
        tags = {s.tag for s in numbering.sections('fr')}
        refs = set()
        for q in grade.get_questions_ordered():
            refs |= set(re.findall(r'@@ref:([a-z0-9_-]+)@@', _text(q.description)))
        assert refs and refs <= tags, refs - tags

    def test_translations(self, lab):
        """Every tr() text has its English in _TRANSLATIONS, the twelve instructor texts among them (the
        markup kept: checked for every lab of the directory by test_draft_misc_translations.py)."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == set(tr_strings) and all(english.values())
        assert all(english[k] != k for k in english)
        literals = _instructor_literals()
        assert len(literals) == 12 and set(literals) <= set(english)
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)', fr)) == set(re.findall(r'\{(\w+)', en)), fr[:60]
        # evaluated at import time, before _TRANSLATIONS: the English is inline
        assert lab.title.resolve('en') == 'Open vSwitch: VLANs, bonding, tunnels, stateful firewall and QoS'
        for state in ('solve_part1', 'solve_part2', 'solve_part3', 'solve_part4', 'solve_part5', 'solve_bonus', 'final'):
            description = getattr(lab.NetScheme, state)._sre_state_description
            assert description.resolve('en') == english[description.resolve('fr')], state

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data)
        questions = grade.get_questions_ordered()
        assert len(questions) == 12
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 5
        for q in questions:
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert form_spec.form_fields(fr) == form_spec.form_fields(en)
            assert strip_instructor(fr) != fr, _text(q.title)
            assert unwrap_instructor(fr) != unwrap_instructor(en), _text(q.title)

    def test_hashes_are_pinned(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data)
        hashes = [q.question_hash for q in grade.get_questions_ordered()]
        assert len(set(hashes)) == 12 and all(re.fullmatch(r'[0-9a-f]{16}', h) for h in hashes)
        assert _LAB_PATH.read_text().count('hash="') == 12

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
        assert result.calls == 12 and result.translations == 12
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'openvswitch_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('openvswitch_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the student texts stays, that of the instructor texts goes
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(set(_instructor_literals()))
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6)
