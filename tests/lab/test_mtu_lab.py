"""Offline tests of the MTU lab (lab/sre/mtu.py): data generation, the state ops (the probes' permanent
black hole, the user states `black_hole` / `icmp_restored`, the reference solution), the two-pass grading
contract with synthetic outputs (nothing done: 0 on every element, everything done: 40, the WAN-MTU fix,
a host-only fix, the language-neutral dropdown values), the texts in both languages (no leak of the
operator's MTU, the instructor solutions, the numbered course, the translations), the stripped lab file
and the English identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of the
real tools (nft list ruleset, ip -j -d link show, iperf3 -J, ping).
"""
import ast
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import pmtu  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / 'mtu.py'
_INSTRUCTOR_CALLS = 7          # organisation + (solution, answers) of each of the three parts


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('mtu_lab_under_test', _LAB_PATH)
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


def _cmds(ops, machine):
    return [str(op) for (_, m), op_list in ops.items() if m == machine for op in op_list if isinstance(op, str)]


def _files(ops, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for (_, m), op_list in ops.items() if m == machine for op in op_list if not isinstance(op, str)}


def _states(lab):
    return {name: getattr(lab.NetScheme, name) for name in dir(lab.NetScheme)
            if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)}


# ---------------------------------------------------------------------------
# synthetic outputs
# ---------------------------------------------------------------------------

def _ping_ok(dest, count=2):
    lines = [f"PING {dest} ({dest}) 56(84) bytes of data."]
    lines += [f"64 bytes from {dest}: icmp_seq={k + 1} ttl=63 time=0.4 ms" for k in range(count)]
    lines += ["", f"--- {dest} ping statistics ---",
              f"{count} packets transmitted, {count} received, 0% packet loss, time 300ms",
              "rtt min/avg/max/mdev = 0.300/0.400/0.500/0.100 ms", ""]
    return "\n".join(lines)


def _ping_too_long(dest, mtu):
    return (f"PING {dest} ({dest}) {mtu - 27}({mtu + 1}) bytes of data.\n"
            f"ping: local error: message too long, mtu={mtu}\n\n--- {dest} ping statistics ---\n"
            f"1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n")


def _iperf3(received):
    return json.dumps({'start': {}, 'end': {'sum_sent': {'bytes': received, 'retransmits': 0},
                                            'sum_received': {'bytes': received, 'seconds': 2.0,
                                                             'bits_per_second': received * 4.0}}}, indent=1)


def _links(lab, ns, machine, scenario):
    d = ns.data
    links = [{'ifname': 'lo', 'mtu': 65536, 'flags': ['LOOPBACK', 'UP', 'LOWER_UP']}]
    for i in range(len(ns.net_config[machine])):
        wan_side = lab.WAN_IFACE.get(machine) == f"eth{i}"
        links.append({'ifname': f"eth{i}", 'mtu': d.wan_mtu if wan_side and scenario['wan_mtu_fix'] else 1500,
                      'flags': ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP']})
    if scenario['tunnel'] and machine in ('r1', 'r2'):
        local, remote = (d.ips.r1_wan1.ip, d.ips.r2_wan2.ip) if machine == 'r1' else (d.ips.r2_wan2.ip, d.ips.r1_wan1.ip)
        links.append({'ifname': 'gre1', 'mtu': d.wan_mtu - pmtu.GRE_OVERHEAD,
                      'flags': ['POINTOPOINT', 'NOARP', 'UP', 'LOWER_UP'],
                      'linkinfo': {'info_kind': 'gre', 'info_data': {'local': str(local), 'remote': str(remote),
                                                                     'ttl': 64, 'pmtudisc': True}}})
    return json.dumps(links)


def _synthetic(lab, ns, machine, command, scenario):
    """(output, code) of *command* on *machine* in the project described by *scenario*."""
    d = ns.data
    tun_mtu = d.wan_mtu - pmtu.GRE_OVERHEAD
    if not scenario['started']:
        return '', 0
    if command == 'nft list ruleset':
        if scenario['clamp'] and machine in ('r1', 'r2'):
            return pmtu.nft_mss_clamp(lab.CLAMP_TABLE, mss4=pmtu.mss_for(d.wan_mtu)).replace('    ', '\t'), 0
        return '', 0
    if command == 'ip -j -d link show':
        return _links(lab, ns, machine, scenario), 0
    if '.sre_mtu_a' in command:                                     # the transfers between the probes
        received = 5_000_000 if scenario['clamp'] or scenario['wan_mtu_fix'] else 0
        return f"===A\n{_iperf3(received)}\n===R\n{_iperf3(received)}\n", 0
    if command.startswith('ping -c '):                              # eval_ping h1 -> h2
        return _ping_ok(command.split()[-1]), 0
    if command.startswith('echo "===T"'):                           # the tunnel seen from r1
        if not scenario['tunnel']:
            return "===T\nping: connect: Network is unreachable\n===FIT\n===OVER\n", 2
        dest = str(d.ips.r2_tun.ip)
        return f"===T\n{_ping_ok(dest)}\n===FIT\n{_ping_ok(dest)}\n===OVER\n{_ping_too_long(dest, tun_mtu)}", 0
    if 'echo flushed' in command:
        return 'flushed\nserver\n' if machine == 'h2' else 'flushed\n', 0
    return '', 0


_EVERYTHING = {'started': True, 'clamp': True, 'wan_mtu_fix': False, 'tunnel': True, 'answers': True}
_NOTHING = {'started': True, 'clamp': False, 'wan_mtu_fix': False, 'tunnel': False, 'answers': False}


def _simulate(lab, data, tmp_pub_dir, instructor_mode=False, **changes):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme)."""
    scenario = dict(_EVERYTHING, **changes)
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            if scenario['answers']:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = _synthetic(lab, ns, m, key[0], scenario)
        step += 1
    return grade, ns


def _regrade(grade):
    grade.reset_before_grade()
    grade.grade()
    return _by_title(grade)


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _set_answer(grade, field, value):
    """Change one form answer, keeping the others (the cheat answers)."""
    for q in grade.get_questions_ordered():
        if any(f['name'] == field for f in (getattr(q, 'fields', None) or [])):
            form = json.loads(grade._answers[q.question_hash])
            form[field] = value
            grade._answers[q.question_hash] = json.dumps(form)
            return
    raise KeyError(field)


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()
        assert lab.Data.from_json(data.to_json()).wan_mtu == data.wan_mtu

    def test_operator_mtu(self, lab):
        for d in [lab.Data.generate() for _ in range(30)]:
            assert d.wan_mtu in lab.MTU_CHOICES
            assert d.wan_mtu - pmtu.GRE_OVERHEAD >= 1280 and pmtu.max_ping_payload(d.wan_mtu) < 1472
            assert d.nets.tun.prefixlen == 30 and d.ips.r1_tun.ip != d.ips.r2_tun.ip
            assert d.ips.r1_tun in [d.ips.r1_tun] and d.ips.r1_tun.network == d.nets.tun


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_states_and_descriptions(self, lab):
        states = _states(lab)
        assert {'initial', 'restore', 'black_hole', 'icmp_restored', 'final'} <= set(states)
        allowed = {n for n, f in states.items() if f._sre_state_user_allowed}
        assert allowed == {'black_hole', 'icmp_restored'}
        # evaluated at import time, before _TRANSLATIONS: the inline English must be the table's
        for name in sorted(allowed):
            description = states[name]._sre_state_description
            assert description.resolve('en') == lab._TRANSLATIONS['en'][description.resolve('fr')]
            assert description.resolve('en') != description.resolve('fr')
        assert lab.title.resolve('en') == lab._TRANSLATIONS['en'][lab.title.resolve('fr')]

    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        wan = _cmds(ops, 'wan')
        assert f"ip link set dev eth0 mtu {data.wan_mtu}; ip link set dev eth1 mtu {data.wan_mtu}" in wan
        probes = _files(ops, 'wan')[lab.PROBE_RULES]
        assert f"table inet {lab.PROBE_TABLE} " in probes
        assert str(data.ips.h1.ip) in probes and str(data.ips.h2.ip) in probes
        assert any(f"nft -f {lab.PROBE_RULES}" in c for c in wan)
        # the table of the user state is written, not loaded
        assert lab.BLACK_HOLE_RULES in _files(ops, 'wan')
        assert not any(f"nft -f {lab.BLACK_HOLE_RULES}" in c for c in wan)
        assert any(f"iperf3 -s -D -p {lab.GRADE_PORT}" in c for c in _cmds(ops, 'h2'))

    def test_user_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'black_hole')
        assert any(f"nft -f {lab.BLACK_HOLE_RULES}" in c for c in _cmds(ops, 'wan'))
        for m in lab.STUDENT_MACHINES:
            assert "ip route flush cache" in _cmds(ops, m)
        assert not any(lab.PROBE_TABLE in c for c in _cmds(ops, 'wan'))
        ops = _state_ops(ns, 'icmp_restored')
        assert _cmds(ops, 'wan') == [f"nft delete table inet {lab.BLACK_HOLE_TABLE} 2>/dev/null; true"]

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        assert not _cmds(ops, 'wan')
        for r in ('r1', 'r2'):
            assert f"size set {pmtu.mss_for(data.wan_mtu)}" in _files(ops, r)[lab.CLAMP_RULES]
            assert any(f"mtu {data.wan_mtu - pmtu.GRE_OVERHEAD} up" in c for c in _cmds(ops, r))


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrade:
    def test_nothing_done_gives_zero_everywhere(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, **_NOTHING)
        assert {t: e.grade for t, e in _by_title(grade).items() if e.grade} == {}
        assert _totals(grade) == (0, 40)
        # a fresh project answers the ping between the probes: not a point by itself
        assert _by_title(grade)['bh_connectivity'].grade == 0

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _totals(grade) == (40, 40), {t: (e.grade, e.max_grade) for t, e in _by_title(grade).items()}
        assert [str(p.title) for p in grade.get_grade_parts()] == ['part1', 'part2', 'part3']

    def test_wan_mtu_fix_instead_of_clamping(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, clamp=False, wan_mtu_fix=True)
        assert _totals(grade) == (40, 40)

    def test_host_only_fix(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, clamp=False)
        _set_answer(grade, 'fix', 'host_probing')
        elements = _regrade(grade)
        lost = {t: e.max_grade for t, e in elements.items() if e.grade != e.max_grade}
        assert lost == {'bh_forward': 5, 'bh_backward': 5, 'bh_connectivity': 2, 'bh_config': 2, 'bh_q_fix': 2}

    def test_dropdown_values(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for value, points in (('mss_clamping', 2), ('wan_mtu', 2), ('host_probing', 0), ('host_route', 0),
                              ('MSS clamping nftables sur r1 et/ou r2', 0)):
            _set_answer(grade, 'fix', value)
            assert _regrade(grade)['bh_q_fix'].grade == points, value
        for value, points in (('wan', 1), ('nobody', 0), ('r1', 0)):
            _set_answer(grade, 'fragmenter', value)
            assert _regrade(grade)['fragmenting_machine'].grade == points, value

    def test_cheat_answers_are_dropdown_values(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        answers = grade.get_cheat_answers('final')
        for q in grade.get_questions_ordered():
            if not getattr(q, 'fields', None):
                continue
            form = json.loads(answers[q.question_hash])
            for lang in ('fr', 'en'):
                for name, spec in re.findall(r'@@\{([^:}~]+)(?:~\d*)?:>([^}]*)\}@@', _text(q.description, lang)):
                    values = [c.split('>>>', 1)[-1] for c in spec.split('|')]
                    assert form[name] in values, (lang, name, form[name])


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

def _all_texts(grade, ns, lang='fr'):
    texts = [('informations', _text(ns.informations, lang))]
    for q in grade.get_questions_ordered():
        texts.append((_text(q.title, lang), _text(q.description, lang)))
    for e in grade.get_grade_list():
        texts.append((str(e.title), _text(e.description, lang) if e.description else ''))
    return texts


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 4
        for lang in ('fr', 'en'):
            assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0, lang))
            assert len([w for w, t in _all_texts(g1, ns1, lang) if has_instructor(t)]) == 4

    def test_operator_mtu_never_shown_to_students(self, lab, data, tmp_pub_dir):
        """Outside instructor mode the texts are the same whatever the operator's MTU."""
        other = lab.Data.from_json(data.to_json())
        other.wan_mtu = next(m for m in lab.MTU_CHOICES if m != data.wan_mtu)
        g0, ns0 = _simulate(lab, data, tmp_pub_dir)
        g1, ns1 = _simulate(lab, other, tmp_pub_dir)
        for lang in ('fr', 'en'):
            assert _all_texts(g0, ns0, lang) == _all_texts(g1, ns1, lang), lang
        # the instructor texts do show it
        g2, ns2 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            assert f"**{data.wan_mtu}**" in _text(g2.get_questions_ordered()[0].description, lang)

    def test_instructor_texts_in_both_languages(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(en) and fr != en
            assert '**Solution.**' in en or '**For the instructor.**' in en
        import check_sre_translations as cst
        tree = ast.parse(_LAB_PATH.read_text())
        assert set(lab._TRANSLATIONS) == {'en'}
        assert set(lab._TRANSLATIONS['en']) == cst.get_tr_strings(tree)
        assert None not in lab._TRANSLATIONS['en'].values()
        instructor = [v for v in lab._TRANSLATIONS['en'].values()
                      if v.lstrip().startswith(('**Solution.**', '**Answers.**', '**For the instructor.**'))]
        assert len(instructor) == _INSTRUCTOR_CALLS

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for lang in ('fr', 'en'):
            for where, text in _all_texts(g1, ns1, lang):
                assert "{'" not in text, (lang, where)
                assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), (lang, where)
                markdown_to_html(text, show_instructor=True)
                markdown_to_html(text, show_instructor=False)
        resolved, numbering = resolve_informations(ns1.informations)
        for lang in ('fr', 'en'):
            assert [s.number for s in numbering.sections(lang) if s.level == 1] == ['1', '2', '3', '4', '5']
            assert [s.number for s in numbering.sections(lang) if s.level == 2] == [
                '1.1', '1.2', '1.3', '1.4', '1.5', '2.1', '2.2', '2.3']
            assert '@@' not in _text(resolved, lang)
        english = _text(resolved, 'en')
        assert '## <a id="gre"></a>3. GRE tunnel and encapsulation overhead' in english
        assert '### <a id="remedies"></a>2.3. The remedies' in english
        assert '- [3. GRE tunnel and encapsulation overhead](#gre)' in english
        assert '[3](#gre))' in english and 'PMTUD black hole: section [2.2](#blackhole)' in english
        french = _text(resolved)
        assert '## <a id="gre"></a>3. Tunnel GRE et surcoût d\'encapsulation' in french
        assert 'trou noir PMTUD : section [2.2](#blackhole)' in french
        # the references of a question resolve to bare section numbers, in both languages
        q2 = g1.get_questions_ordered()[2]
        description = resolve_text(TranslatedText.from_value(q2.description, 'fr'), numbering)
        assert '(onglet *Informations*, section 2.3)' in description.resolve('fr')
        assert '(*Informations* tab, section 2.3)' in description.resolve('en')

    def test_form_fields(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = [f['name'] for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        assert names == ['mtu', 'payload', 'icmp_type', 'icmp_code', 'fragmenter', 'mss', 'command', 'capture',
                         'explanation', 'fix', 'rt_mtu', 'overhead', 'mtu_tunnel']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == _INSTRUCTOR_CALLS and result.warnings == []
        stripped = tmp_path / 'mtu_stripped.py'
        stripped.write_bytes(result.data)
        calls = [n.func.id for n in ast.walk(ast.parse(result.data)) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name)]
        assert b'_TRANSLATIONS' in result.data and 'instructor' not in calls
        spec = importlib.util.spec_from_file_location('mtu_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert len(kept) == len(lab._TRANSLATIONS['en']) - _INSTRUCTOR_CALLS
        assert not any(v.lstrip().startswith(('**Solution.**', '**Answers.**', '**For the instructor.**'))
                       for v in kept.values())
        assert kept['Tunnel GRE entre r1 et r2'] == 'GRE tunnel between r1 and r2'
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (40, 40)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, nft tables, data fields, grade elements, parts and form fields."""
        french = re.compile(r'(sonde|trou|noir|retabli|partie|charge|^qui|outil|explication|correctif|surcout|'
                            r'joignable|aller|retour|connectivite)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(_states(lab))
        names += [lab.PROBE_TABLE, lab.BLACK_HOLE_TABLE, lab.CLAMP_TABLE, lab.TUN_DEV]
        names += [Path(p).stem for p in (lab.PROBE_RULES, lab.BLACK_HOLE_RULES, lab.CLAMP_RULES)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
