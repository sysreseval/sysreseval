"""Offline tests of lab/sre/_DRAFT_misc2/voip.py (VoIP: SIP / RTP with Asterisk), without Docker.

lab_eval_initial.json and lab_eval_final.json (tests/mock_data/voip/) are two real evaluations of
the lab (z04, 2026-11-12, sysreseval/voip:1.32): the data of the instance and every grader command
with its output, on a fresh project (0/100) and once the ``final`` state was applied (100/100 + 10
bonus).  The commands of the grader depend on the lab data only, so a replay with that data must
register exactly the archived commands and give the archived grades: a change of a command, of a
check or of a grade element shows here.  After a deliberate change of the commands, capture both
files again (``sre cat --json`` of the two evaluations, the private keys of the data blanked).
"""
import copy
import html
import importlib.util
import json
import re
import sys
from datetime import datetime
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from SRE import form_spec, params  # noqa: E402
from SRE.command import preload_images  # noqa: E402
from SRE.informations import resolve_informations, resolve_text  # noqa: E402
from SRE.instructor_text import markdown_to_html, strip_instructor, unwrap_instructor  # noqa: E402
import check_sre_translations  # noqa: E402
import strip_instructor as strip_tool  # noqa: E402
import voip  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc2' / 'voip.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'voip'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('voip_lab_under_test', _LAB_PATH)
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
    return json.loads((_MOCK / f'{name}.json').read_text())


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
    (*patch*: a function changing the {key: (output, code)} table first).  Returns (grade, ns)."""
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
    return grade, ns


def _totals(grade):
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.max_grade for e in elements if not e.bonus),
            sum(e.grade for e in elements if e.bonus))


def _grades(grade) -> dict:
    return {str(e.title): e.grade for e in grade.get_grade_list()}


def _text(value, lang='fr'):
    return value.get(lang) if isinstance(value, dict) else value


# ---------------------------------------------------------------------------
# replay of two real evaluations
# ---------------------------------------------------------------------------

class TestReplay:
    def test_final(self, lab, tmp_pub_dir):
        evaluation = _evaluation('lab_eval_final')
        grade, _ = _replay(lab, evaluation, answers='final')
        assert _totals(grade) == (100, 100, 10)
        assert _grades(grade) == {e['title']: e['grade'] for e in evaluation['grades']}
        assert evaluation['errors'] == []

    def test_initial(self, lab, tmp_pub_dir):
        evaluation = _evaluation('lab_eval_initial')
        grade, _ = _replay(lab, evaluation)
        assert _totals(grade) == (0, 100, 0)
        assert _grades(grade) == {e['title']: e['grade'] for e in evaluation['grades']}

    def test_commands_are_one_line(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, _evaluation('lab_eval_final'), answers='final')
        commands = [key[0] for tests in grade.get_tests().values() for key in tests]
        assert len(commands) == 19
        assert all('\n' not in c and '@@@' not in c for c in commands)


def _patch_json_line(outputs, machine, step, marker, change):
    """Apply *change* to the JSON document printed by the command of *machine* / *step* containing *marker*."""
    for key, (output, code) in list(outputs.items()):
        if key[0] == machine and key[1] == step and marker in key[2]:
            document = json.loads(output.strip().splitlines()[-1])
            change(document)
            outputs[key] = (json.dumps(document), code)
            return
    raise AssertionError(f"no command {marker!r} on {machine} at step {step}")


class TestChecks:
    """The real outputs of the solved lab, changed in one point: only the matching elements fall."""

    @staticmethod
    def lost(lab, patch):
        evaluation = _evaluation('lab_eval_final')
        grade, _ = _replay(lab, evaluation, answers='final', patch=patch)
        reference = {e['title']: e['grade'] for e in evaluation['grades']}
        return sorted(title for title, value in _grades(grade).items() if value != reference[title])

    def test_a_reinvite_breaks_the_media_path(self, lab, tmp_pub_dir):
        def patch(outputs):
            _patch_json_line(outputs, 'probe_office', 2, ' run ', lambda d: d['results']['internal'].update(
                reinvites=[{'method': 'INVITE', 'address': '10.9.9.9', 'port': 40000}]))
        assert self.lost(lab, patch) == ['media_through_pbx']

    def test_the_tos_byte(self, lab, tmp_pub_dir):
        def patch(outputs):
            def change(document):
                for name in ('internal', 'echo'):
                    document['results'][name]['rtp']['tos'] = {'0': 200}
            _patch_json_line(outputs, 'probe_office', 2, ' run ', change)
        assert self.lost(lab, patch) == ['dscp_ef']

    def test_refusals_count_only_with_the_good_call(self, lab, tmp_pub_dir):
        def patch(outputs):
            _patch_json_line(outputs, 'pbx2', 2, ' run ', lambda d: d['results']['trunk_in'].update(
                status=403, answered=False, rtp={}))
        assert self.lost(lab, patch) == ['trunk_authentication', 'trunk_context', 'trunk_inbound']

    def test_an_accepted_unauthenticated_trunk(self, lab, tmp_pub_dir):
        def patch(outputs):
            _patch_json_line(outputs, 'pbx2', 2, ' run ', lambda d: d['results']['trunk_no_auth'].update(
                status=200, answered=True))
        assert self.lost(lab, patch) == ['trunk_authentication']

    def test_the_voicemail_message_of_this_evaluation_only(self, lab, tmp_pub_dir):
        def patch(outputs):
            for key, (output, code) in list(outputs.items()):
                if key[0] == 'pbx' and key[1] == 3 and '/1004/INBOX/' in key[2]:
                    outputs[key] = (re.sub(r'origtime=(\d+)', lambda m: f"origtime={int(m.group(1)) - 3600}", output),
                                    code)
        assert self.lost(lab, patch) == ['voicemail_message']

    def test_the_teleworker_must_hear_the_caller(self, lab, tmp_pub_dir):
        def patch(outputs):
            for key, (output, code) in list(outputs.items()):
                if key[0] == 'probe_home' and key[1] == 3:
                    lines = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
                    for entry in lines:
                        if entry.get('event') == 'call':
                            entry['rtp'] = {'received': 0, 'heard': []}
                    outputs[key] = ('\n'.join(json.dumps(e) for e in lines) + '\n===END\n', code)
        assert self.lost(lab, patch) == ['nat_media']

    def test_caller_name_from_the_phone(self, lab, tmp_pub_dir):
        """The PBX passes on the display name the caller announced (no callerid on its endpoint)."""
        def patch(outputs):
            for key, (output, code) in list(outputs.items()):
                if key[0] == 'probe_office' and key[1] == 3:
                    lines = [json.loads(line) for line in output.splitlines() if line.startswith('{')]
                    for entry in lines:
                        if entry.get('user') == '1003' and entry.get('from_user') == '1004':
                            entry['from_display'] = 'Probe'
                    outputs[key] = ('\n'.join(json.dumps(e) for e in lines) + '\n===END\n', code)
        assert self.lost(lab, patch) == ['caller_id']


# ---------------------------------------------------------------------------
# data, machines, states
# ---------------------------------------------------------------------------

class TestLab:
    def test_data(self, lab, data):
        numbers = [a['number'] for a in data.accounts]
        assert numbers == list(lab.NUMBERS) and len({a['name'] for a in data.accounts}) == len(numbers)
        assert all(a['password'].isalnum() and len(a['password']) == 10 and len(a['pin']) == 4 for a in data.accounts)
        assert data.rtp_start % 2 == 0 and 20000 <= data.rtp_start and data.rtp_end < 40400
        assert data.rtp_start > 20000 - 1  # never the default range of Asterisk (10000-20000)
        assert data.ivr_digit_answering != data.ivr_digit_busy and data.demo_expires >= 60
        assert data.demo_number not in numbers and data.demo_ptime in (20, 30, 40)
        assert data.ips.probe_office.ip in data.nets.office and data.ips.laptop.ip in data.nets.home
        again = lab.Data.from_json(data.to_json())
        assert again.accounts == data.accounts and again.ips.box_wan == data.ips.box_wan

    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert specs['pbx']['privileged'] and specs['pbx']['entrypoint'] == '/sbin/init'
        assert all('/voip:' in specs[m]['image'] for m in ('pbx', 'pbx2', 'phone1', 'phone2', 'laptop', 'monitor'))
        assert specs['probe_office']['hidden'] and specs['probe_home']['hidden'] and not specs['pbx2']['allow_connection']
        assert params.sre_docker_image('voip') in preload_images._extract_images_from_file(_LAB_PATH)

    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        assert all('\n' not in str(op) for ops_ in ops.values() for op in ops_ if isinstance(op, str))
        pjsip = _files(ops, 1, 'pbx')[lab.PJSIP_CONF]
        assert f'[{data.demo_number}]' in pjsip and '[1001]' not in pjsip and 'transport-udp' in pjsip
        assert 'masquerade' in _files(ops, 1, 'box')['/etc/nftables.conf']
        config = _files(ops, 1, 'phone1')['/root/.baresip/config']
        assert 'ausine,400' in config and 'snd_path\t\t/shared/phone1' in config
        accounts = _files(ops, 1, 'phone1')['/root/.baresip/accounts']
        assert all(line.startswith('#') for line in accounts.splitlines())  # the account is the student's job
        assert not any(a['password'] in accounts for a in data.accounts)
        daemons = {m: _spec_of(c) for (s, m), cmds in ops.items() if s == 3 for c in _cmds(ops, s, m)
                   if ' daemon ' in c}
        assert set(daemons) == {'probe_office', 'pbx2', 'probe_home'}
        assert [a['user'] for a in daemons['probe_office']['accounts']] == [data.demo_number, '1003', '1004']
        assert daemons['probe_office']['accounts'][0]['calls']['number'] == data.demo_service
        assert [a['mode'] for a in daemons['pbx2']['accounts']] == ['answer', 'busy']
        assert daemons['probe_home']['accounts'][0]['refresh'] == 15  # under the 30 s of the box's UDP mapping
        assert 'systemctl restart asterisk 2>&1' in _cmds(ops, 2, 'pbx')

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        files = _files(ops, 1, 'pbx')
        pjsip = files[lab.PJSIP_CONF]
        for account in data.accounts:
            assert f'[{account["number"]}](' in pjsip and f'password = {account["password"]}' in pjsip
            assert f'{account["number"]} => {account["pin"]},{account["name"]}' in files[lab.VOICEMAIL_CONF]
        assert data.trunk_password_in in pjsip and data.trunk_password_out in pjsip and 'protocol = tls' in pjsip
        assert f'rtpstart = {data.rtp_start}' in files[lab.RTP_CONF]
        extensions = files[lab.EXTENSIONS_CONF]
        assert f'exten => {data.ivr_digit_busy},1,Dial(PJSIP/1004,15)' in extensions and '[from-site-b]' in extensions
        for machine, number in lab.SOFTPHONES.items():
            assert f'<sip:{number}@' in _files(ops, 1, machine)['/root/.baresip/accounts']
            assert any('baresip -f /root/.baresip -d' in c for c in _cmds(ops, 2, machine))

    def test_pbx2(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        pjsip, extensions = ns._pbx2_pjsip(), ns._pbx2_extensions()
        assert f'password = not-{data.trunk_password_in}' in pjsip  # the trunk with a wrong password
        assert f'contact = sip:{ns.ip("pbx")}:5060' in pjsip and f'match = {ns.ip("pbx")}' in pjsip
        assert '_81.,1,Dial(PJSIP/${EXTEN:2}@site-a-noauth,10)' in extensions

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(telephone|poste|appel|messagerie|routeur|passerelle|sonde|serveur|reseau|boite|'
                            r'compte|numero|annonce|enregistr|repondeur|chiffr|bureau|maison|teletravail)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._network_specs)
        names += [n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False)]
        names += list(lab.Data.__dataclass_fields__) + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', [])]
        bad = [n for n in names if french.search(n)]
        assert not bad, bad
        assert sorted(n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False)) == [
            'final', 'initial']


def _state_ops(ns, name):
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    return {(step, machine): list(ops) for step, by_machine in ns._ops.items() for machine, ops in by_machine.items()}


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if hasattr(op, 'filename') and hasattr(op, 'content')}


def _spec_of(command):
    words = command.split()
    return json.loads(voip.base64.urlsafe_b64decode(words[words.index(voip.PROBE_PATH) + 2]))


# ---------------------------------------------------------------------------
# texts: translations, rendering, stripped file
# ---------------------------------------------------------------------------

def _texts(lab, data, tmp_pub_dir):
    """(course, numbering, grade) with the instructor texts on."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    try:
        ns = lab.NetScheme(data=data, running_lab_name=name)
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
    finally:
        marker.unlink()
    course, numbering = resolve_informations(ns.informations)
    return course, numbering, grade


WORD_RE = re.compile(r"[A-Za-zÀ-ÿ0-9_]{4,}")


def _words_lost(source, rendered):
    """The first word of *source* that does not come out in order in *rendered* (None: all there)."""
    plain = html.unescape(re.sub(r"<[^>]+>", ' ', rendered))
    source = re.sub(r'<a id="[^"]*"></a>', ' ', re.sub(r"\]\(#[^)]*\)", ']', source))
    position = 0
    for match in WORD_RE.finditer(source):
        found = plain.find(match.group(0), position)
        if found < 0:
            return source[max(0, match.start() - 50):match.end() + 50]
        position = found + len(match.group(0))
    return None


class TestTexts:
    def test_translations(self, lab):
        assert check_sre_translations.check_file(_LAB_PATH) == 0
        assert set(lab._TRANSLATIONS) == {'en'} and None not in lab._TRANSLATIONS['en'].values()
        assert sum(v.lstrip().startswith(('**Solution.**', '**Answers.**', '**For the instructor.**'))
                   for v in lab._TRANSLATIONS['en'].values()) == 9

    def test_french_and_english(self, lab, data, tmp_pub_dir):
        course, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        texts = [course] + [q.description for q in questions] + [q.title for q in questions]
        texts += [e.description for e in grade.get_grade_list()] + [p.description for p in grade.get_grade_parts()]
        for text in texts:
            assert _text(text, 'fr') != _text(text, 'en'), _text(text, 'fr')[:60]
        for question in questions:  # the forms of both languages store the same answers
            assert form_spec.form_fields(_text(question.description, 'fr')) == form_spec.form_fields(
                _text(question.description, 'en'))
        assert sum(bool(form_spec.form_fields(_text(q.description))) for q in questions) == 2
        assert _text(lab.title, 'en') == "VoIP: SIP and RTP with Asterisk"

    @pytest.mark.parametrize('lang', ['fr', 'en'])
    def test_rendering(self, lab, data, tmp_pub_dir, lang):
        """Every text comes out of the markdown conversion whole (no fence swallowed by a list, no
        inline `</` eating a paragraph), the instructor fragments shown or not."""
        course, numbering, grade = _texts(lab, data, tmp_pub_dir)
        texts = {'informations': _text(course, lang)}
        for index, question in enumerate(grade.get_questions_ordered()):
            texts[f'question {index}'] = resolve_text(_text(question.description, lang), numbering)
        for name, text in texts.items():
            assert "{'" not in text and not re.search(r"(?<![${])\{[a-z_][a-z0-9_]*\}", strip_instructor(text)), name
            for show in (False, True):
                rendered = markdown_to_html(text, show_instructor=show)
                assert '```' not in rendered, (name, show)
                lost = _words_lost(unwrap_instructor(text) if show else strip_instructor(text), rendered)
                assert lost is None, (name, show, lost)
            if name != 'informations':
                assert strip_instructor(text) != text, f"{name} has no instructor() solution"

    def test_stripped_lab_file(self):
        source = _LAB_PATH.read_bytes()
        result = strip_tool.strip_source(source)
        assert b'instructor(tr(' not in result.data and not result.warnings, result.warnings
        compile(result.data, 'voip_stripped', 'exec')
        assert source.count(b'instructor(tr(') == 9 == result.calls == result.translations and result.import_removed
        for text in (b'**Solution.**', b"Pour l'enseignant", b'For the instructor', b'**Answers.**'):
            assert text not in result.data
