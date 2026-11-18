"""Offline tests of lab/sre/_DRAFT_misc/aaa.py (AAA: FreeRADIUS, LDAP, TOTP, device administration, EAP,
802.1X, Kerberos), without Docker.

lab_eval_initial.json and lab_eval_final.json (tests/mock_data/aaa/) are two real evaluations of the lab
(s16, 2026-11-18, sysreseval/aaa:1.33): the data of the instance and every grader command with its output,
on a fresh project (0/100) and once the ``final`` state was applied (100/100 + 10 bonus).  The commands of
the grader depend on the lab data only, so a replay with that data must register exactly the archived
commands and give the archived grades.  Mixing the two evaluations part by part checks the independence
of the parts: the outputs of one part taken from the solved project give that part all its points and
nothing else, and the solved project without them loses exactly those points.  After a deliberate change of
the commands, capture both files again (``sre cat --json`` of the two evaluations, the private keys of the
data blanked).
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
from SRE.informations import resolve_informations, resolve_text  # noqa: E402
from SRE.instructor_text import markdown_to_html, strip_instructor, unwrap_instructor  # noqa: E402
import check_sre_translations  # noqa: E402
import strip_instructor as strip_tool  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'aaa.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'aaa'
PARTS = ('part1', 'part2', 'part3', 'part4', 'part5', 'part6', 'part7', 'part8', 'part9', 'bonus')


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('aaa_lab_under_test', _LAB_PATH)
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


def _replay(lab, evaluation, answers=None, patch=None, outputs=None):
    """grade() pass after pass like run_tests(), the results of each step taken from *evaluation* (or
    *outputs*; *patch*: a function changing the {key: (output, code)} table first).  Returns grade."""
    outputs = dict(outputs if outputs is not None else _outputs(evaluation))
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


def _grades(grade) -> dict:
    return {str(e.title): e.grade for e in grade.get_grade_list()}


def _lost(grade) -> dict:
    return {str(e.title): e.max_grade - e.grade for e in grade.get_grade_list() if e.grade != e.max_grade}


def _text(value, lang='fr'):
    return value.get(lang) if isinstance(value, dict) else value


def part_of(machine: str, command: str) -> str:
    """The part a grader command belongs to (``diag``: a diagnostic, graded nowhere)."""
    if machine == 'sw':
        return 'part1' if 'radclient' in command else 'part6' if 'hostapd_cli' in command and 'all_sta' in command \
            else 'diag'
    if machine == 'radius':
        if 'eapol_test' in command:
            return 'part5'
        if 'radclient' in command:
            for login, part in (('emma', 'part2'), ('hugo', 'part2'), ('ines', 'part2'), ('remy', 'part3'),
                                ('auditor', 'part4')):
                if f'User-Name = \\"{login}\\"' in command:
                    return part
        return 'diag'
    if machine == 'ldap':
        return 'part2'
    if machine == 'router':
        return 'part4' if 'radclient' in command else 'diag'
    if machine in ('pc1', 'pc2'):
        return 'diag' if 'journalctl' in command else 'part6'
    if machine == 'nac':
        return 'part6'
    if machine == 'kdc':
        return 'diag' if 'kadm5.acl' in command else 'part7'
    if machine == 'srv':
        return 'part8' if 'klist -k' in command or 'GssapiCredStore' in command else 'diag'
    if machine == 'ws':
        return 'part9' if 'sre_login_probe' in command else 'diag'
    if machine == 'probe':
        if command.startswith('ping'):
            return 'part6'
        if 'sre_login_probe' in command:
            return 'part4' if 'router.corp.lan' in command else 'part9'
        if 'researcher' in command:
            return 'bonus'
        if 'dev2' in command or 'curl' in command:
            return 'part8'
        return 'part7'
    raise AssertionError(f"unclassified command on {machine}: {command[:80]}")


# ---------------------------------------------------------------------------
# replay of two real evaluations
# ---------------------------------------------------------------------------

class TestReplay:
    def test_final(self, lab, tmp_pub_dir):
        evaluation = _evaluation('lab_eval_final')
        grade = _replay(lab, evaluation, answers='final')
        assert _totals(grade) == (100, 100, 10)
        assert _grades(grade) == {e['title']: e['grade'] for e in evaluation['grades']['grade_list']}
        assert evaluation['errors'] == []

    def test_initial(self, lab, tmp_pub_dir):
        evaluation = _evaluation('lab_eval_initial')
        grade = _replay(lab, evaluation)
        assert _totals(grade) == (0, 100, 0)
        assert _grades(grade) == {e['title']: e['grade'] for e in evaluation['grades']['grade_list']}

    def test_commands_are_one_line(self, lab, tmp_pub_dir):
        grade = _replay(lab, _evaluation('lab_eval_final'), answers='final')
        commands = [key[0] for tests in grade.get_tests().values() for key in tests]
        assert all('\n' not in c and '@@@' not in c for c in commands)
        assert {part_of(m, c) for (m, _), tests in grade.get_tests().items() for c, _ in tests} == set(PARTS) | {'diag'}

    def test_only_choice_answers_are_exo_only(self, lab, tmp_pub_dir):
        grade = _replay(lab, _evaluation('lab_eval_final'), answers='final')
        choices = {'answer_password', 'answer_eap_inner', 'answer_first_frame'}
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in choices else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title


class TestIndependence:
    """Each part alone gives its points, everything but one part loses exactly its points."""

    @staticmethod
    def _mixed(evaluation_base, evaluation_part, part):
        outputs = _outputs(evaluation_base)
        others = _outputs(evaluation_part)
        for key in outputs:
            if part_of(key[0], key[2]) == part:
                outputs[key] = others[key]
        return outputs

    @pytest.mark.parametrize('part', PARTS)
    def test_part_alone(self, lab, tmp_pub_dir, part):
        initial, final = _evaluation('lab_eval_initial'), _evaluation('lab_eval_final')
        grade = _replay(lab, final, outputs=self._mixed(initial, final, part))
        for e in grade.get_grade_list():
            behavioural = not str(e.title).startswith('answer_')
            expected = e.max_grade if (e.grade_part == part and behavioural) else 0
            assert e.grade == expected, (part, e.title)

    @pytest.mark.parametrize('part', PARTS)
    def test_all_but_one(self, lab, tmp_pub_dir, part):
        initial, final = _evaluation('lab_eval_initial'), _evaluation('lab_eval_final')
        grade = _replay(lab, final, answers='final', outputs=self._mixed(final, initial, part))
        lost = _lost(grade)
        assert lost, part
        by = {str(e.title): e for e in grade.get_grade_list()}
        assert all(by[t].grade_part == part and not t.startswith('answer_') and by[t].grade == 0 for t in lost), lost


def _patch(outputs, machine, marker, change, step=None):
    """Apply *change* (old output → new output) to the command of *machine* containing *marker*."""
    hits = 0
    for key, (output, code) in list(outputs.items()):
        if key[0] == machine and marker in key[2] and (step is None or key[1] == step):
            outputs[key] = (change(output), code)
            hits += 1
    assert hits, (machine, marker)


class TestChecks:
    """One point of the solved project changed: only the matching elements fall."""

    def _lost_after(self, lab, *patches):
        def patch(outputs):
            for p in patches:
                _patch(outputs, *p)
        return _lost(_replay(lab, _evaluation('lab_eval_final'), answers='final', patch=patch))

    def test_pc3_reachable(self, lab, tmp_pub_dir):
        def reachable(outputs):
            for key, (out, code) in list(outputs.items()):
                if key[0] == 'probe' and key[2].startswith('ping') and key[2].split()[5].endswith('.103'):
                    outputs[key] = (out, 0)
        lost = _lost(_replay(lab, _evaluation('lab_eval_final'), answers='final', patch=reachable))
        assert lost == {'dot1x_pc3_blocked': 3}

    def test_logoff_leaves_the_port_open(self, lab, tmp_pub_dir):
        lost = self._lost_after(lab, ('pc1', 'logoff', lambda out: out.replace('LOGOFF=closed', 'LOGOFF=open')))
        assert lost == {'dot1x_logoff_closes': 2, 'dot1x_logon_reopens': 1}

    def test_wrong_vlan(self, lab, tmp_pub_dir):
        lost = self._lost_after(lab, ('radius', 'User-Name = \\"hugo\\", User-Password',
                                      lambda out: re.sub(r'Tunnel-Private-Group-Id:0 = "\d+"',
                                                         'Tunnel-Private-Group-Id:0 = "1"', out)))
        assert lost == {'ldap_vlan_guest': 3}

    def test_password_alone_accepted(self, lab, tmp_pub_dir):
        def accept(out):
            return out.replace('Received Access-Reject', 'Received Access-Accept')
        lost = self._lost_after(lab, ('radius', 'User-Name = \\"remy\\", User-Password = \\"' , accept))
        assert lost == {'totp_password_alone': 2, 'totp_wrong_code': 1}

    def test_helpdesk_too_powerful(self, lab, tmp_pub_dir):
        lost = self._lost_after(lab, ('probe', 'addprinc -randkey sreprobe-new',
                                      lambda out: 'Principal "sreprobe-new@CORP.LAN" created.\n===RC 0\n'))
        assert lost == {'krb_helpdesk_limited': 1}

    def test_keytab_readable_by_everyone(self, lab, tmp_pub_dir):
        lost = self._lost_after(lab, ('srv', 'GssapiCredStore', lambda out: out.replace('STAT=640', 'STAT=644')))
        assert lost == {'krb_http_keytab': 1}

    def test_no_accounting(self, lab, tmp_pub_dir):
        lost = self._lost_after(lab, ('nac', 'detail-', lambda out: out.replace('Acct-Status-Type = Start',
                                                                                'Acct-Status-Type = Interim-Update')))
        assert lost == {'dot1x_accounting': 3}

    def test_no_ticket_after_login(self, lab, tmp_pub_dir):
        lost = self._lost_after(lab, ('ws', 'sre_login_probe', lambda out: out.replace('"tgt": true', '"tgt": false')))
        assert lost == {'pam_krb5_ticket': 1}


# ---------------------------------------------------------------------------
# the lab: data, machines, states
# ---------------------------------------------------------------------------

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


class TestLab:
    def test_data(self, lab, data):
        assert len(data.passwords) == 19
        for login, pw in data.passwords.items():
            assert len(pw) >= lab.POLICY_MIN_LENGTH and re.search('[a-z]', pw) and re.search('[A-Z]', pw) \
                and re.search('[0-9]', pw), login
        assert len({str(getattr(data.ips, m)) for m in lab.HOST_PARTS}) == len(lab.HOST_PARTS)
        assert all(str(getattr(data.macs, pc)).upper().startswith('02-53-52') for pc in lab.PCS)
        assert 10 <= data.vlan_staff <= 99 and 100 <= data.vlan_guest <= 199
        assert re.fullmatch('[A-Z2-7]{16}', data.totp_secret)
        assert lab.Data.from_json(data.to_json()).passwords == data.passwords

    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert all(s['image'] == lab.AAA_IMAGE for s in specs.values())
        assert specs['probe'].get('hidden') and specs['probe'].get('allow_connection') is False
        assert specs['nac'].get('allow_connection') is False and specs['ldap'].get('allow_connection') is False
        assert {m for m, s in specs.items() if s.get('entrypoint') == '/sbin/init'} == set(lab.SYSTEMD_MACHINES)
        assert lab.export_kathara_project is False

    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        assert set(m for _, m in ops) == set(specs for specs in lab.NetScheme._machine_specs)
        sw = ' '.join(_cmds(ops, 1, 'sw'))
        assert 'ip link add br0 type bridge' in sw and 'master br0' in sw and 'hostapd' not in sw
        radius = _cmds(ops, 1, 'radius')
        assert any('freeradius-pristine' in c for c in radius)
        assert {'/root/ca/ca.key', '/var/lib/sre-probe/peap.conf'} <= set(_files(ops, 1, 'radius'))
        kdc = ' '.join(_cmds(ops, 1, 'kdc'))
        assert 'kdb5_util create -s -r CORP.LAN' in kdc and 'addprinc -randkey host/kdc.corp.lan' in kdc
        # no machine resolves its own name to a loopback address
        assert all('127.0.1.1' not in f.get('/etc/hosts', '') for f in (_files(ops, 1, m) for m in lab.PCS))
        for (_, m), lst in ops.items():
            assert all('\n' not in str(op) for op in lst if isinstance(op, str)), m

    def test_final_steps(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        # kadmind is restarted on kdc at step 1: srv talks to it at step 2; the supplicants start after hostapd
        assert _cmds(ops, 1, 'srv') == [] and any('ktadd' in c for c in _cmds(ops, 2, 'srv'))
        assert any('restart krb5-admin-server' in c for c in _cmds(ops, 1, 'kdc'))
        assert any('hostapd@eth1' in c for c in _cmds(ops, 1, 'sw'))
        assert all(_cmds(ops, 1, pc) == [] and _cmds(ops, 2, pc) for pc in ('pc1', 'pc2'))
        assert 'GSSAPIStrictAcceptorCheck no' in _files(ops, 2, 'srv')[lab.SSHD_KERBEROS_CONF]
        site = _files(ops, 1, 'radius')['/etc/freeradius/3.0/sites-available/default']
        assert 'Auth-Type LDAP' in site and 'totp' in site
        users = _files(ops, 1, 'radius')['/etc/freeradius/3.0/mods-config/files/authorize']
        assert users.startswith('DEFAULT\tHuntgroup-Name == "devices"')

    def test_part_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        states = sorted(n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False))
        assert states == sorted(['initial', 'final'] + list(PARTS))
        assert not any(lab.NetScheme.is_state_user_allowed(s) for s in states)
        part1 = _state_ops(ns, 'part1')
        assert set(m for _, m in part1) == {'radius'}
        users = _files(part1, 1, 'radius')['/etc/freeradius/3.0/mods-config/files/authorize']
        assert 'alice' in users and 'remy' not in users and 'DEFAULT' not in users

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|serveur|reseau|poste|compte|sonde|annuaire|royaume|commutateur|'
                            r'utilisateur|mot_de_passe|motdepasse|chiffr|cle_|jeton|invite)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._network_specs)
        names += [n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False)]
        names += list(lab.Data.__dataclass_fields__) + list(data.passwords)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', None) or []]
        bad = [n for n in names if french.search(n)]
        assert not bad, bad


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
    def test_instructor_translations(self, lab):
        """Every instructor text exists in French and English (the other texts are French only for now);
        no English entry is left over."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        english = lab._TRANSLATIONS['en']
        assert set(english) <= set(tr_strings) and None not in english.values()
        assert len(english) == 42 and all(english[k] != k for k in english if k.strip() != '**Solution.**')
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**')) for v in english.values()) == 19

    def test_instructor_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        for question in grade.get_questions_ordered():
            fr, en = _text(question.description, 'fr'), _text(question.description, 'en')
            assert strip_instructor(fr) != fr, _text(question.title)
            assert unwrap_instructor(fr) != unwrap_instructor(en) or fr == en, _text(question.title)
        for question in grade.get_questions_ordered():   # the forms of both languages store the same answers
            assert form_spec.form_fields(_text(question.description, 'fr')) == form_spec.form_fields(
                _text(question.description, 'en'))
        assert sum(bool(form_spec.form_fields(_text(q.description))) for q in grade.get_questions_ordered()) == 5
        assert _text(lab.title, 'en') == "AAA: RADIUS, 802.1X, two-factor authentication and Kerberos"

    def test_rendering(self, lab, data, tmp_pub_dir):
        """Every text comes out of the markdown conversion whole (no fence swallowed by a list, no
        inline `</` eating a paragraph), the instructor fragments shown or not."""
        course, numbering, grade = _texts(lab, data, tmp_pub_dir)
        texts = {'informations': _text(course)}
        for index, question in enumerate(grade.get_questions_ordered()):
            texts[f'question {index}'] = resolve_text(_text(question.description), numbering)
        for name, text in texts.items():
            assert "{'" not in text and not re.search(r"(?<![${%])\{[a-z_][a-z0-9_]*\}", strip_instructor(text)), name
            for show in (False, True):
                rendered = markdown_to_html(text, show_instructor=show)
                assert '```' not in rendered, (name, show)
                lost = _words_lost(unwrap_instructor(text) if show else strip_instructor(text), rendered)
                assert lost is None, (name, show, lost)

    def test_stripped_lab_file(self):
        source = _LAB_PATH.read_bytes()
        result = strip_tool.strip_source(source)
        assert b'instructor(tr(' not in result.data and not result.warnings, result.warnings
        compile(result.data, 'aaa_stripped', 'exec')
        assert result.calls == 20 and result.translations == 42 and result.import_removed
        for text in (b'**Solution.**', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
