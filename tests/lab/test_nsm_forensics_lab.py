"""Offline tests of lab/sre/_DRAFT_misc/nsm-forensics.py (Zeek, a pcap investigation, Cowrie), without Docker.

tests/mock_data/nsm/lab/ holds real evaluations of the lab (s16, 2026-11-25, images sretest/base13 / init13 /
nsm13:1.36, Zeek 9.0.1, Cowrie 3.1.8), exported with ``sre cat --json``: a fresh project (``lab_eval_initial``,
0), a fresh project once ``final`` was applied twice (``lab_eval_final2``, 100 + 6 bonus), then one fresh
project per part state (``lab_eval_part1_sensor`` ... ``lab_eval_bonus_intel``), each applied alone, and
``lab_eval_mistakes`` (``final``, then five deliberate mistakes made by hand, 88 + 0: see test_live_mistakes).  The
commands of the grader depend on the lab data only, so a replay with the data of an evaluation must register
exactly its archived commands and give its archived grades.  After a deliberate change of the grader's
commands, capture them again (``sre cat --json`` of the evaluations).
"""
import ast
import base64
import copy
import hashlib
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
import pcap_gen  # noqa: E402
import suricata_pcap  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'nsm-forensics.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'nsm' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'part1': (13, 5), 'part2': (14, 0), 'part3': (2, 22), 'part4': (23, 4), 'part5': (0, 17), 'bonus': (6, 0)}
ALONE = {'part1_sensor': 'part1', 'part2_scripts': 'part2', 'part3_investigation': 'part3',
         'part4_honeypot': 'part4', 'part5_correlation': 'part5', 'bonus_intel': 'bonus'}
FORMS = {'q_zeek', 'q_scan', 'q_bruteforce', 'q_download', 'q_c2', 'q_exfil', 'q_honeypot', 'q_attackers',
         'q_compromise'}
CHOICE_FORMS = {'q_zeek', 'q_honeypot'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nsm_forensics_lab_under_test', _LAB_PATH)
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
    (*answers*: the cheat answers of that state; *patch*: a function changing the outputs first)."""
    outputs = _outputs(evaluation)
    if patch is not None:
        patch(outputs)
    ns = lab.NetScheme(data=_data_of(lab, evaluation), running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade._default_language = 'fr'
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
        assert _totals(grade) == (0, 100, 0)

    def test_final(self, lab):
        grade = _replay(lab, _evaluation('final2'), answers='final')
        assert _totals(grade) == (100, 100, 6) and _lost(grade) == {}
        assert _parts(grade) == {part: sum(points) for part, points in POINTS.items()}

    def test_final_without_answers(self, lab):
        grade = _replay(lab, _evaluation('final2'))
        forms = sum(points[1] for points in POINTS.values())
        assert _totals(grade) == (100 - forms, 100, 6) and set(_lost(grade)) == FORMS

    @pytest.mark.parametrize('state', sorted(ALONE))
    def test_part_alone(self, lab, state):
        """Each part state applied alone on a fresh project gives its behavioural points and nothing else,
        and all the points of its part with its own cheat answers."""
        evaluation = _evaluation(state)
        part = ALONE[state]
        parts = _parts(_replay(lab, evaluation))
        assert parts[part] == POINTS[part][0], parts
        assert all(points == 0 for name, points in parts.items() if name != part), parts
        parts = _parts(_replay(lab, evaluation, answers=state))
        assert parts[part] == sum(POINTS[part]), parts
        assert all(points == 0 for name, points in parts.items() if name != part), parts

    def test_live_mistakes(self, lab):
        """``final``, then by hand on the live project: the private address space left local and zeekctl
        deployed again, ``&write_expire`` in web-scan.zeek, userdb.txt removed (Cowrie's defaults), the input
        chain of the honeypot's firewall deleted, spaces instead of tabs in intel.dat."""
        grade = _replay(lab, _evaluation('mistakes'), answers='final')
        assert _lost(grade) == {'zeek_local_nets': 4, 'scan_quiet': 1, 'admin_port_wan_closed': 2, 'cowrie_userdb': 5,
                                'intel_domain': 2, 'intel_addr': 2, 'intel_url': 2}
        assert _totals(grade) == (88, 100, 0)

    def test_scopes(self, lab):
        grade = _replay(lab, _evaluation('final2'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in CHOICE_FORMS), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {'intel_domain', 'intel_addr', 'intel_url'}

    @pytest.mark.parametrize('patch, lost', [
        # Site::private_address_space_is_local left at T: the probe of wan is local too
        (lambda lab, d: _patch_output('sensor', 3, '/conn.log', lambda out: out.replace(
            '"local_orig":false', '"local_orig":true')), {'zeek_local_nets': 4}),
        # the HTTP request not logged (no JSON log of it)
        (lambda lab, d: _patch_output('sensor', 3, '/http.log', lambda out: ''), {'zeek_json': 3}),
        # the DNS query not logged
        (lambda lab, d: _patch_output('sensor', 3, '/dns.log', lambda out: ''), {'zeek_dns': 3}),
        # Zeek captures on eth0
        (lambda lab, d: _patch_output('sensor', 1, 'pgrep -a -x zeek', lambda out: out.replace('-i eth1', '-i eth0')),
         {'zeek_capture': 3}),
        # &write_expire: the 404 spread at 40 s intervals raise a notice too
        (lambda lab, d: _add_notice(lab, d, 'webscan', {'note': 'SRE::Web_Scan', 'src': lab.web_scan_cases(d)['slow']['src']}),
         {'scan_quiet': 1}),
        # a notice for every new connection, the received ones included
        (lambda lab, d: _add_notice(lab, d, 'honeypot', {'note': 'SRE::Honeypot_Outbound',
                                                         'id.orig_h': lab.wan_addr(d, 120), 'id.resp_p': 22}),
         {'outbound_quiet': 2}),
        # Cowrie not on port 22
        (lambda lab, d: _patch_output('probe', 2, 'SRE-BANNER-p22', lambda out: re.sub(
            r'SRE-BANNER-p22=.*', 'SRE-BANNER-p22=', out)), {'cowrie_banner': 3}),
        # the admin port open from wan
        (lambda lab, d: _patch_output('probe', 2, 'SRE-BANNER-wanadmin', lambda out: out.replace(
            'SRE-BANNER-wanadmin=', 'SRE-BANNER-wanadmin=SSH-2.0-OpenSSH_10.0p2')), {'admin_port_wan_closed': 2}),
        # the default userdb: root accepted with any password
        (lambda lab, d: _patch_output('honeypot', 3, 'cowrie.json', lambda out: "\n".join(
            line.replace('"cowrie.login.failed"', '"cowrie.login.success"') if '"username":"root"' in line else line
            for line in out.splitlines())), {'cowrie_userdb': 2}),
        # the URL indicator not matched (a space instead of a tab in intel.dat)
        (lambda lab, d: _patch_output('sensor', 1, '/tmp/sre-zeek-offline/intel;', lambda out: "\n".join(
            line for line in out.splitlines() if 'HTTP::IN_URL' not in line)), {'intel_url': 2}),
        # another file extracted
        (lambda lab, d: _patch_output('analyst', 1, 'sha256sum', lambda out: out.replace(d.incident['sha256'], '0' * 64)),
         {'extracted_file': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final2')
        grade = _replay(lab, evaluation, answers='final', patch=patch(lab, _data_of(lab, evaluation)))
        assert _lost(grade) == lost


def _add_notice(lab, data, name, notice):
    """A patch of the offline run *name* of sensor adding one notice."""
    line = 'SRE-ZEEK-LOG notice ' + json.dumps(dict({'ts': 1.0}, **notice), separators=(',', ':'))
    return _patch_output('sensor', 1, f'/tmp/sre-zeek-offline/{name};', lambda out: out.rstrip('\n') + '\n' + line + '\n')


# ---------------------------------------------------------------------------
# data, evidence, topology, states
# ---------------------------------------------------------------------------


def _tcp_packets(pcap: bytes):
    """[(ts, src, dst, sport, dport, flags, payload)] of the TCP packets of a capture."""
    out = []
    for _, ts, _, _, _, frame in pcap_gen._iter_packets(pcap):
        ip = frame[14:]
        if ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl:]
        off = (tcp[12] >> 4) * 4
        out.append((ts, '.'.join(map(str, ip[12:16])), '.'.join(map(str, ip[16:20])),
                    int.from_bytes(tcp[0:2], 'big'), int.from_bytes(tcp[2:4], 'big'), tcp[13], tcp[off:]))
    return out


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        assert data.nets.wan.subnet_of(IPv4Network('198.18.0.0/15'))
        assert all(n.is_private and n.prefixlen == 24 for n in (data.nets.dmz, data.nets.lan))
        assert 6 <= data.scan_threshold <= 12
        hp = data.honeypot
        assert hp['root_refused'] not in hp['root_passwords'] and len(set(hp['root_passwords'])) == 3
        assert hp['unknown'] != hp['user2'] and ':' not in ''.join(map(str, hp.values()))

    def test_incident_capture(self, lab, data):
        """The answers of part 3 are in the capture."""
        inc = data.incident
        pcap = lab.build_incident_pcap(data)
        assert pcap == lab.build_incident_pcap(data)
        tcp = _tcp_packets(pcap)
        synack = {sport for _, src, dst, sport, _, flags, _ in tcp
                  if src == inc['files'] and dst == inc['scanner'] and flags == 0x12}
        assert synack == set(inc['open_ports'])
        streams = {}            # the victim's connections to the intranet (it browses there too), by client port
        for _, src, dst, sport, dport, _, p in tcp:
            if src == inc['intranet'] and dst == inc['victim']:
                streams[dport] = streams.get(dport, b'') + p
        dropper = [s for s in streams.values() if b'Content-Type: application/x-sh' in s]
        assert len(dropper) == 1
        assert hashlib.sha256(dropper[0].split(b'\r\n\r\n', 1)[1]).hexdigest() == inc['sha256']
        logins = b''.join(p for _, src, _, _, dport, _, p in tcp if src == inc['scanner'] and dport == 80)
        assert logins.count(b'POST /login') == len(inc['wordlist']) + 1
        assert f"password={lab.quote_plus(inc['password'])}".encode() in logins
        beacons = sorted(ts for ts, src, dst, _, _, _, p in tcp
                         if src == inc['victim'] and dst == inc['c2_ip'] and p.startswith(b'GET /api/v2/ping'))
        assert len(beacons) == inc['beacons']
        assert all(abs(b - a - inc['period']) < 0.5 for a, b in zip(beacons, beacons[1:]))
        names = lab.exfil_names(inc)
        assert bytes.fromhex(''.join(n.split('.')[0] for n in names)).decode() == inc['secret']
        for name in names:
            assert name.encode().split(b'.')[0] in pcap

    def test_history(self, lab, data):
        """The answers of part 5 are in the generated logs."""
        events, conns, answers = lab.build_history(data.history, data)
        assert answers == data.history['answers']
        failed = Counter(e['src_ip'] for e in events if e['eventid'] == 'cowrie.login.failed')
        assert failed.most_common(1)[0][0] == answers['top_ip'] and failed.most_common(2)[1][1] < failed[answers['top_ip']]
        assert len({e['src_ip'] for e in events if e['eventid'].startswith('cowrie.login')}) == answers['n_ips']
        downloads = [e for e in events if e['eventid'] == 'cowrie.session.file_download']
        assert len(downloads) == 1 and downloads[0]['url'] == answers['url'] and downloads[0]['shasum'] == answers['sha256']
        session = downloads[0]['session']
        connect = next(e for e in events if e['session'] == session and e['eventid'] == 'cowrie.session.connect')
        ssh = [c for c in conns if c['id.orig_h'] == connect['src_ip'] and c['id.orig_p'] == connect['src_port']]
        assert [c['uid'] for c in ssh] == [answers['ssh_uid']] and ssh[0]['id.resp_p'] == 22
        outbound = [c for c in conns if c['id.orig_h'] == str(data.ips.honeypot.ip)]
        assert [c['uid'] for c in outbound] == [answers['out_uid']]
        assert any(answers['key_comment'] in e.get('input', '') for e in events if e['session'] == session)
        assert len({c['uid'] for c in conns}) == len(conns)

    def test_offline_captures(self, lab, data):
        for spec in (lab.web_scan_spec(data), lab.honeypot_spec(data), lab.training_spec(data), lab.intel_spec(data)):
            assert suricata_pcap.build_pcap(spec)[:4] == b'\xd4\xc3\xb2\xa1'
        grading, training = lab.web_scan_cases(data, 1), lab.web_scan_cases(data, 0)
        assert not {c['src'] for c in grading.values()} & {c['src'] for c in training.values()}
        assert grading['exact']['count'] == data.scan_threshold == grading['below']['count'] + 1
        indicators = lab.intel_indicators(data)
        assert indicators[1][0] == lab.wan_addr(data, lab.INTEL_HOST)
        events = lab.intel_spec(data)['events']
        assert min(e['at'] for e in events[1:]) >= 3.0

    def test_probe_roles(self, lab, data):
        addresses = [lab.role_addr(data, r) for r in lab.PROBE_ROLES]
        used = {str(getattr(data.ips, k).ip) for k in lab.ADDRESSES}
        cases = {c['src'] for v in (0, 1) for c in lab.web_scan_cases(data, v).values()}
        assert len(set(addresses)) == 2 and not used & set(addresses) and not cases & (used | set(addresses))
        assert lab.wan_addr(data, lab.INTEL_HOST) not in used | set(addresses) | cases

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert {m.name for m in ns.get_machines()} == {'attacker', 'probe', 'gw', 'www', 'honeypot', 'sensor', 'analyst'}
        assert lab.NetScheme._machine_specs['probe']['hidden']
        assert lab.NetScheme._network_specs['dmz']['mode'] == 'hub'
        assert lab._TOPOLOGY['dmz']['sensor'] == 1 and lab._TOPOLOGY['lan']['sensor'] == 0
        assert ns.get_weight() == 94

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        assert 'ip link set eth1 up' in text and lab.INCIDENT_PCAP in text and lab.TRAINING_PCAP in text
        for state in ('final', *ALONE):
            assert ns.compute_state_ops(state)[0], state
        # final is the union of the part states (part 5 has forms only)
        final, _ = ns.compute_state_ops('final')
        count = sum(len(v) for st in final.values() for v in st.values())
        parts = sum(len(v) for state in ALONE if state != 'part5_correlation'
                    for st in ns.compute_state_ops(state)[0].values() for v in st.values())
        assert count == parts

    def test_reference_files(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert '&create_expire=2min' in ns.web_scan_text() and f'threshold = {data.scan_threshold}' in ns.web_scan_text()
        assert f'const honeypot = {data.ips.honeypot.ip}' in ns.honeypot_script_text()
        assert 'event new_connection' in ns.honeypot_script_text()
        assert 'redirect to :2222' in ns.nft_text() and f'ip saddr != {data.nets.lan} drop' in ns.nft_text()
        userdb = ns.userdb_text().splitlines()
        assert userdb[3] == 'root:x:!*' and userdb[-1] == f"{data.honeypot['user2']}:x:*"
        lines = ns.intel_text().splitlines()
        assert lines[0].count('\t') == 4 and len(lines) == 4 and all(line.count('\t') == 3 for line in lines[1:])
        assert lab.PRIVATE_NOT_LOCAL in ' '.join(ns.sensor_cmds())

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|attaquant|partie|miel|journal|enquete)', re.I)
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
        assert 'final' in names and 'part4_honeypot' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _texts(lab, data):
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    grade._default_language = 'fr'
    grade.reset_before_grade()
    grade.grade()
    course, numbering = resolve_informations(ns.informations)
    return course, numbering, grade


class TestTexts:
    def test_course(self, lab, data, tmp_pub_dir):
        course, numbering, _ = _texts(lab, data)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'nsm', 'response', 'zeek', 'zeek-logs', 'zeekctl', 'zeek-cut', 'scripting', 'notice', 'intel', 'pcap',
            'patterns', 'honeypot', 'cowrie', 'cowrie-logs', 'correlation', 'memo']
        text = _text(course)
        assert '@@' not in text
        # no value of the instance and no summary of the questions in the course
        for value in (data.token, str(data.nets.dmz.network_address), data.honeypot['hostname'], data.honeypot['sensor'],
                      data.honeypot['kernel'], lab.FAKE_BANNER, data.incident['c2_domain'], 'Partie 1', 'SRE::Web_Scan'):
            assert value not in text, value

    def test_instructor_translations(self, lab):
        tree = ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        english = lab._TRANSLATIONS['en']
        assert set(english) <= set(tr_strings) and None not in english.values() and len(english) == 23
        assert all(english[k] != k for k in english)

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data)
        solutions = [q for q in grade.get_questions_ordered() if 'olution' in _text(q.description, 'fr')
                     or "enseignant" in _text(q.description, 'fr')]
        assert len(solutions) >= 13
        for q in solutions:
            assert _text(q.description, 'fr') != _text(q.description, 'en')

    def test_rendering(self, lab, data, tmp_pub_dir):
        course, numbering, grade = _texts(lab, data)
        questions = grade.get_questions_ordered()
        assert len(questions) == 16
        texts = {'informations': _text(course)}
        for index, q in enumerate(questions):
            for lang in ('fr', 'en'):
                texts[f'question {index} {lang}'] = _text(resolve_text(q.description, numbering), lang)
        for name, text in texts.items():
            assert "{'" not in text and '@@ref' not in text, name
            assert not re.search(r"(?<![${%@])\{[a-z_][a-z0-9_]*\}", strip_instructor(text)), name
            for show in (False, True):
                assert '```' not in markdown_to_html(text, show_instructor=show), (name, show)
        with_solution = [q for q in questions if strip_instructor(_text(q.description, 'fr')) != _text(q.description, 'fr')]
        assert len(with_solution) == 15
        for q in with_solution:
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert unwrap_instructor(fr) != unwrap_instructor(en), _text(q.title)
            assert form_spec.form_fields(fr) == form_spec.form_fields(en)

    def test_stripped_lab_file(self, tmp_path):
        result = strip_tool.strip_source(_LAB_PATH.read_bytes())
        assert b'instructor(' not in result.data and not result.warnings, result.warnings
        assert result.calls == 15 and result.translations == 23
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'nsm_forensics_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('nsm_forensics_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert _totals(_replay(module, _evaluation('final2'), answers='final')) == (100, 100, 6)

    def test_question_hashes_are_pinned(self):
        tree = ast.parse(_LAB_PATH.read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr in ('question_dummy', 'question_form', 'question_text')]
        assert len(calls) == 16
        hashes = [next(k.value.value for k in c.keywords if k.arg == 'hash') for c in calls]
        assert len(set(hashes)) == 16 and all(re.fullmatch(r'[0-9a-f]{16}', h) for h in hashes)

    def test_forms(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade._default_language = 'fr'
        grade.reset_before_grade()
        grade.grade()
        cheat = grade.get_cheat_answers('final')
        forms = [q for q in grade.get_questions_ordered() if form_spec.form_fields(_text(q.description))]
        assert len(forms) == len(cheat) == 9
        for q in forms:
            names = {f['name'] for f in form_spec.form_fields(_text(q.description))}
            assert set(json.loads(cheat[q.question_hash])) == names
