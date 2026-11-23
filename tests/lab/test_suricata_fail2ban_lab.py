"""Offline tests of lab/sre/_DRAFT_misc/suricata-fail2ban.py (Suricata IDS / IPS and fail2ban), without Docker.

tests/mock_data/suricata/lab/ holds nine real evaluations of the lab (s17, 2026-11-23, images
sretest/base13 / init13:1.34, Suricata 7.0.10, fail2ban 1.1.0), exported with ``sre cat --json``: a fresh
project (``lab_eval_initial``, 0) and the same project once ``final`` was applied (``lab_eval_final``,
124 + 6 bonus), then one fresh project per part state (``lab_eval_part1_sensor`` ... ``lab_eval_bonus_gw``),
each applied alone.  The commands of the grader depend on the lab data only, so a replay with the data of
an evaluation must register exactly its archived commands and give its archived grades.  After a
deliberate change of the grader's commands, capture them again (``sre cat --json`` of the evaluations).
"""
import copy
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
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
import suricata_pcap  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'suricata-fail2ban.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'suricata' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'part1': (15, 5), 'part2': (24, 4), 'part3': (6, 4), 'part4': (17, 4), 'part5': (18, 4),
          'part6': (16, 7), 'bonus': (6, 0)}
ALONE = {'part1_sensor': 'part1', 'part2_signatures': 'part2', 'part3_tuning': 'part3', 'part4_ips': 'part4',
         'part5_ssh': 'part5', 'part6_intranet': 'part6', 'bonus_gw': 'bonus'}
FORMS = {'q_sensor', 'q_rules', 'q_false_positives', 'q_ips', 'q_f2b_table', 'q_f2b_admin', 'q_history',
         'q_filter_traps'}
TYPED_FORMS = {'q_f2b_table', 'q_history'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('suricata_fail2ban_lab_under_test', _LAB_PATH)
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


class TestReplay:
    def test_initial(self, lab):
        grade = _replay(lab, _evaluation('initial'))
        assert _totals(grade) == (0, 124, 0)

    def test_final(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        assert _totals(grade) == (124, 124, 6) and _lost(grade) == {}
        assert _parts(grade) == {part: sum(points) for part, points in POINTS.items()}

    def test_final_without_answers(self, lab):
        grade = _replay(lab, _evaluation('final'))
        assert _totals(grade) == (124 - 28, 124, 6) and set(_lost(grade)) == FORMS

    @pytest.mark.parametrize('state', sorted(ALONE))
    def test_part_alone(self, lab, state):
        """Each part state applied alone on a fresh project gives its behavioural points and nothing else."""
        grade = _replay(lab, _evaluation(state))
        part = ALONE[state]
        parts = _parts(grade)
        assert parts[part] == POINTS[part][0], parts
        assert all(points == 0 for name, points in parts.items() if name != part), parts

    def test_scopes(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            if str(e.title) in FORMS - TYPED_FORMS:
                assert e.scope == params.EXO_EVAL_SCOPE, e.title
            else:
                assert e.scope != params.EXO_EVAL_SCOPE, e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {'bonus_gw_blocks_scanner', 'bonus_gw_jail'}

    @pytest.mark.parametrize('patch, lost', [
        # the encoded traversal no longer detected (an http.uri.raw rule)
        (lambda lab, d: _patch_offline(lab, d, 'signatures', drop=('pw_encoded', 1000011)), {'sig_passwd': 2}),
        # a C2 rule without endswith also fires on a name containing the domain
        (lambda lab, d: _patch_offline(lab, d, 'signatures', add=('c2_inside', 1000012)), {'sig_c2': 2}),
        # the noisy rule silenced for everybody
        (lambda lab, d: _patch_offline(lab, d, 'tuning', drop=('lan_other', 1000100)), {'tuning_suppress': 4}),
        # the offline run failed (not even the control signature)
        (lambda lab, d: _patch_offline(lab, d, 'tuning', drop_all=True), {'tuning_suppress': 6}),
        # the sensor saw nothing
        (lambda lab, d: _patch_output('ids', 3, '"signature_id":1000001,', lambda out: ''), {'sensor_detects': 6}),
        # the queue without bypass
        (lambda lab, d: _patch_output('ips', 1, 'nft -j list ruleset', lambda out: out.replace(', "flags": "bypass"', '')
                                      .replace(',"flags":"bypass"', '').replace('"flags": "bypass", ', '')),
         {'ips_queue': 2}),
        # an ordinary request blocked: the injections are not counted either
        (lambda lab, d: _patch_output('probe', 2, 'http_code', lambda out: out.replace('good1=200', 'good1=000')),
         {'ips_blocks_injection': 5, 'ips_no_false_block': 3}),
        # successful logins banned (an unanchored filter)
        (lambda lab, d: _patch_output('probe', 3, 'nc -z', lambda out: out.replace('OPEN_webok', 'CLOSED_webok')),
         {'web_ignores_success': 3}),
        # admin banned (no ignoreip)
        (lambda lab, d: _patch_output('admin', 3, 'nc -z', lambda out: out.replace('OPEN_admin', 'CLOSED_admin')),
         {'ssh_spares_admin': 4}),
        # the scanner still passes through gw
        (lambda lab, d: _patch_output('probe', 3, 'nc -z', lambda out: out.replace('CLOSED_scan', 'OPEN_scan')),
         {'bonus_gw_blocks_scanner': 4}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        data = _data_of(lab, evaluation)
        grade = _replay(lab, evaluation, answers='final', patch=patch(lab, data))
        assert _lost(grade) == lost

    def test_injected_address_banned(self, lab):
        evaluation = _evaluation('final')
        victim = lab.role_addr(_data_of(lab, evaluation), 'web_victim')

        def ban_victim(out):
            return out.replace('Banned IP list:\t', f'Banned IP list:\t{victim} ')
        grade = _replay(lab, evaluation, answers='final',
                        patch=_patch_output('intranet', 3, 'fail2ban-client status intranet', ban_victim))
        assert _lost(grade) == {'web_resists_injection': 5}


def _patch_offline(lab, data, name, drop=None, add=None, drop_all=False):
    """A patch of the offline run *name* of ids (``signatures`` / ``tuning``): the alert of a case
    removed (*drop* = (case, sid)), an alert added for a case (*add*), or every alert removed."""
    cases = lab.signature_cases(data, 150, 1) if name == 'signatures' else lab.noise_cases(data, 1)

    def change(out):
        lines = out.splitlines()
        if drop_all:
            return "\n".join(line for line in lines if not line.startswith('SRE-ALERT ')) + "\n"
        if drop:
            case, sid = drop
            src = cases[case]['src']
            lines = [line for line in lines
                     if not (line.startswith('SRE-ALERT ') and f'"sid":{sid},' in line and f'"src":"{src}"' in line)]
        if add:
            case, sid = add
            lines.append('SRE-ALERT ' + json.dumps({'sid': sid, 'src': cases[case]['src'], 'dst': cases[case]['dst'],
                                                    'action': 'allowed'}, separators=(',', ':')))
        return "\n".join(lines) + "\n"
    return _patch_output('ids', 1, f'/tmp/sre-suricata-offline/{name};', change)


# ---------------------------------------------------------------------------
# data, topology, states
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        assert data.nets.wan.subnet_of(IPv4Network('198.18.0.0/15'))
        private = [data.nets.dmz, data.nets.lan, data.nets.apps]
        assert all(n.is_private and n.prefixlen == 24 for n in private) and len({str(n) for n in private}) == 3
        assert not any(n.overlaps(IPv4Network('172.17.0.0/16')) for n in private)
        assert re.fullmatch(r'[a-z-]+\d\d\.example', data.c2_domain)
        assert set(data.passwords) == {'alice', 'bob', 'carol', 'demo'}
        counts = sorted(data.history_attackers.values())
        assert len(counts) == 3 and counts[-1] > counts[-2]

    def test_history(self, lab, data):
        history = lab.render_history(data)
        failures = Counter(line.rsplit('from=', 1)[1] for line in history.splitlines() if ' FAILED login ' in line)
        for address, count in data.history_attackers.items():
            assert failures[address] == count
        top_ip, top_count = lab.top_attacker(data)
        assert failures.most_common(1)[0] == (top_ip, top_count)
        assert all(re.fullmatch(rf"{data.history_day} \d\d:\d\d:\d\d (FAILED|OK) login user=\w+ from=[\d.]+|"
                                rf"{data.history_day} \d\d:\d\d:\d\d INFO health check from=[\d.]+", line)
                   for line in history.splitlines())
        assert lab.render_history(data) == history

    def test_captures(self, lab, data):
        grading, training = lab.signature_cases(data, 150, 1), lab.signature_cases(data, 100, 0)
        assert set(grading) == set(training)
        assert not {e['src'] for e in grading.values()} & {e['src'] for e in training.values()}
        assert len({e['src'] for e in grading.values()}) == len(grading)
        home = [data.nets.dmz, data.nets.lan]
        for case, event in grading.items():
            from_home = any(IPv4Address(event['src']) in n for n in home)
            assert from_home == case.startswith('c2_'), case
        assert data.c2_domain in grading['c2_sub']['qname'].lower() and grading['c2_sub']['qname'] != \
            grading['c2_sub']['qname'].lower()
        for spec in (lab.grading_spec(data), lab.training_spec(data), lab.noise_spec(data)):
            assert suricata_pcap.build_pcap(spec)[:4] == b'\xd4\xc3\xb2\xa1'
        noise = lab.noise_cases(data, 1)
        assert noise['admin_1']['src'] == str(data.ips.admin.ip) != noise['lan_other']['src']

    def test_probe_roles(self, lab, data):
        addresses = [lab.role_addr(data, r) for r in lab.PROBE_ROLES] + \
            [lab.wan_addr(data, h) for h in lab.SSH_UNDER_POOL]
        assert len(set(addresses)) == len(addresses) == 9 + 24
        used = {str(getattr(data.ips, k).ip) for k in lab.ADDRESSES}
        assert not used & set(addresses)

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        machines = {m.name: m for m in ns.get_machines()}
        assert set(machines) == {'attacker', 'probe', 'gw', 'ids', 'bastion', 'intranet', 'admin', 'ips', 'app'}
        assert lab.NetScheme._machine_specs['probe']['hidden']
        assert lab.NetScheme._network_specs['dmz']['mode'] == 'hub'
        assert lab._TOPOLOGY['dmz']['ids'] == 1 and lab._TOPOLOGY['lan']['ids'] == 0

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        assert 'ip link set eth1 up' in text and str(data.ips.ids) in text
        assert 'sre-noisy.rules' in text and 'suricata-gw.yaml' in text and 'intranet.service' in text
        for state in ('final', *ALONE):
            ops, _ = ns.compute_state_ops(state)
            assert ops, state
        # final is the union of the part states
        final, _ = ns.compute_state_ops('final')
        count = sum(len(v) for st in final.values() for v in st.values())
        parts = sum(len(v) for state in ALONE for st in ns.compute_state_ops(state)[0].values() for v in st.values())
        assert count == parts

    def test_reference_files(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        rules = ns.local_rules_text().splitlines()
        assert [re.search(r'sid:(\d+);', r).group(1) for r in rules] == ['1000010', '1000011', '1000012', '1000013']
        assert 'endswith' in rules[2] and data.c2_domain in rules[2]
        assert ns.threshold_line() == f"suppress gen_id 1, sig_id 1000100, track by_src, ip {data.ips.admin.ip}"
        assert 'ExecStart=\n' in ns.ips_dropin_text() and '-q 0' in ns.ips_dropin_text()
        assert str(data.nets.lan) in ns.ssh_jail_text()
        assert 'failregex = ^\\s*FAILED login user=.* from=<HOST>\\s*$' in ns.intranet_filter_text()
        assert 'chain_hook=forward' in ns.gw_jail_text()

    def test_capture_interface(self, lab):
        assert lab.capture_interface("/usr/bin/suricata -D --af-packet -c x", "eth1") == "eth1"
        assert lab.capture_interface("suricata --af-packet=eth1", "eth0") == "eth1"
        assert lab.capture_interface("suricata -c x -i eth1", "eth0") == "eth1"
        assert lab.capture_interface("suricata -D -q 0", "eth1") is None

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|attaquant|partie|regle|prison|journal|passerelle)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.PROBE_ROLES)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields] + [c for f in fields for c in f.get('choices', [])]
        assert 'final' in names and 'part4_ips' in names
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
            'principles', 'placement', 'suricata', 'config', 'eve', 'rules', 'tuning', 'ips', 'fail2ban', 'filter',
            'router-ban', 'limits', 'memo']
        text = _text(course)
        assert '@@' not in text
        # no value of the instance and no summary of the questions in the course
        for value in (data.c2_domain, str(data.nets.dmz.network_address), str(data.ips.admin.ip), 'Partie 1',
                      'sid 1000010', 'sqlmap'):
            assert value not in text, value

    def test_instructor_translations(self, lab):
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        english = lab._TRANSLATIONS['en']
        assert set(english) <= set(tr_strings) and None not in english.values() and len(english) == 25
        assert all(english[k] != k for k in english)

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        assert len(questions) == 15
        for q in questions:
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert strip_instructor(fr) != fr, _text(q.title)
            assert unwrap_instructor(fr) != unwrap_instructor(en), _text(q.title)
            assert form_spec.form_fields(fr) == form_spec.form_fields(en)
        assert sum(bool(form_spec.form_fields(_text(q.description))) for q in questions) == 7

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
        assert b'instructor(tr(' not in result.data and b'instructor(' not in result.data
        assert not result.warnings, result.warnings
        assert result.calls == 15 and result.translations == 25
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'suricata_fail2ban_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('suricata_fail2ban_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (124, 124, 6)
