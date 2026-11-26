"""Offline tests of lab/sre/_DRAFT_misc/scan-hardening.py (scanning with nmap and hardening), without Docker.

tests/mock_data/scan/lab/ holds thirteen real evaluations of the lab (s17, 2026-11-23, images
srescan/scan:1.35 on the published base13 / init13:1.35, nmap 7.95), exported with ``sre cat --json``: a
fresh project (``lab_eval_initial``, 0), the same project once ``final`` was applied (``lab_eval_final``,
132 + 6 bonus), one fresh project per part state (``lab_eval_part1_discovery`` ... ``lab_eval_bonus_nse``),
each applied alone, and ``lab_eval_mistakes``: ``final`` applied on the bonus project, then one mistake per
part (nginx stopped, the firewall of app turned into a reject at policy accept, the explicit MAC list
removed and ``PermitRootLogin prohibit-password``, the secret community accepted from everywhere, vsftpd
enabled again, a serial number hard-coded in the NSE script).  The commands of the grader depend on the lab
data only, so a replay with the data of an evaluation must register exactly its archived commands and give
its archived grades.  After a deliberate change of the grader's commands, capture them again.
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
import nmap_scan  # noqa: E402
import strip_instructor as strip_tool  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'scan-hardening.py'
_MOCK = _REPO / 'tests' / 'mock_data' / 'scan' / 'lab'

#: part -> (behavioural points, form points)
POINTS = {'part1': (4, 8), 'part2': (5, 11), 'part3': (4, 10), 'part4': (4, 14), 'part5': (14, 3),
          'part6': (11, 3), 'part7': (9, 3), 'part8': (14, 2), 'part9': (10, 3), 'bonus': (6, 0)}
ALONE = {'part1_discovery': 'part1', 'part2_ports': 'part2', 'part3_versions': 'part3', 'part4_nse': 'part4',
         'part5_surface': 'part5', 'part6_exposure': 'part6', 'part7_ssh': 'part7', 'part8_web': 'part8',
         'part9_firewall': 'part9', 'bonus_nse': 'bonus'}
FORMS = {'q_discovery', 'q_ports', 'q_versions', 'q_nse', 'q_surface', 'q_exposure', 'q_ssh', 'q_web', 'q_firewall'}
TOTAL = 132
FORM_POINTS = sum(f for _, f in POINTS.values())
#: the tr() literals inside instructor() calls (each one translated, removed by strip-instructor)
INSTRUCTOR_TEXTS = 19


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('scan_hardening_lab_under_test', _LAB_PATH)
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


def _drop_host(xml: str, address: str) -> str:
    """An nmap XML document without its <host> element for *address*."""
    return re.sub(r'<host\b(?:(?!</host>).)*?addr="' + re.escape(address) + r'".*?</host>', '', xml, flags=re.S)


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
        """Each part state applied alone on a fresh project gives its behavioural points and nothing else."""
        grade = _replay(lab, _evaluation(state))
        part = ALONE[state]
        parts = _parts(grade)
        assert parts[part] == POINTS[part][0], parts
        assert all(points == 0 for name, points in parts.items() if name != part), parts

    def test_mistakes(self, lab):
        grade = _replay(lab, _evaluation('mistakes'), answers='final')
        assert _lost(grade) == {
            'web_no_version': 3, 'tls_versions': 3, 'tls_strength': 2, 'web_no_git': 3, 'web_no_backup': 2,
            'web_hsts': 1,                                     # nginx stopped: every web element is gated
            'fw_drop': 1, 'fw_ping': 1,                        # reject at policy accept: closed, not filtered
            'ssh_no_root': 2, 'ssh_weak_mac': 1,               # prohibit-password; default MACs (hmac-sha1)
            'snmp_secret': 3,                                  # the secret community from everywhere
            'legacy_vsftpd_disabled': 1,                       # enabled again (not started)
            'bonus_nse_serial': 4, 'bonus_nse_help': 2,        # a hard-coded serial
        }

    def test_scopes(self, lab):
        grade = _replay(lab, _evaluation('final'), answers='final')
        for e in grade.get_grade_list():
            assert (e.scope == params.EXO_EVAL_SCOPE) == (str(e.title) in FORMS), e.title
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {'bonus_nse_serial', 'bonus_nse_help'}

    @pytest.mark.parametrize('patch, lost', [
        # the discovery file misses the NAS
        (lambda lab, d: _patch_output('attacker', 1, 'discovery.xml',
                                      lambda out: _drop_host(out, str(d.ips.nas.ip))), {'discovery_nas': 2}),
        # a scan of the default ports instead of -p-
        (lambda lab, d: _patch_output('attacker', 1, 'server-tcp.xml',
                                      lambda out: re.sub(r'services="1-65535"', 'services="1-1000"', out)),
         {'tcp_file_all': 3, 'tcp_file_filtered': 2}),
        # root still logs in with the key
        (lambda lab, d: _patch_output('probe', 2, 'deploy@', lambda out: out.replace('root=\n', 'root=LOGIN-OK\n')),
         {'ssh_no_root': 2}),
        # no HSTS header
        (lambda lab, d: _patch_output('probe', 2, 'deploy@', lambda out: re.sub(r'hsts=.*', 'hsts=', out)),
         {'web_hsts': 1}),
        # /.git/HEAD still served over HTTPS
        (lambda lab, d: _patch_output('probe', 2, 'deploy@', lambda out: re.sub(r'git_https=\d+', 'git_https=200', out)),
         {'web_no_git': 3}),
        # vsftpd still enabled
        (lambda lab, d: _patch_output('legacy', 1, 'is-enabled', lambda out: out.replace('vsftpd=disabled', 'vsftpd=enabled')),
         {'legacy_vsftpd_disabled': 1}),
        # Redis without a password
        (lambda lab, d: _patch_output('db', 1, 'redis-cli', lambda out: re.sub(r'noauth=.*', 'noauth=PONG', out)),
         {'redis_password': 3}),
        # /etc/nftables.conf does not load
        (lambda lab, d: _patch_output('app', 1, 'nft -c -f', lambda out: out.replace('===check 0', '===check 1')),
         {'fw_persistent': 2}),
        # the asset service of the probe did not start
        (lambda lab, d: _patch_output('probe', 1, 'sre-asset-service', lambda out: ''),
         {'bonus_nse_serial': 4, 'bonus_nse_help': 2}),
    ])
    def test_one_thing_wrong(self, lab, patch, lost):
        evaluation = _evaluation('final')
        data = _data_of(lab, evaluation)
        grade = _replay(lab, evaluation, answers='final', patch=patch(lab, data))
        assert _lost(grade) == lost


# ---------------------------------------------------------------------------
# data, topology, states, reference files
# ---------------------------------------------------------------------------


class TestLab:
    def test_data(self, lab, data):
        assert lab.Data.from_dict(data.to_dict()).to_dict() == data.to_dict()
        assert data.nets.wan.subnet_of(IPv4Network('198.18.0.0/15'))
        private = [data.nets.office, data.nets.dmz, data.nets.mgmt]
        assert all(n.is_private and n.prefixlen == 24 for n in private) and len({str(n) for n in private}) == 3
        assert len(set(data.office_hosts.values())) == 5 and 1 not in data.office_hosts.values()
        for port in (data.server_ssh_port, data.server_high_port):
            assert port not in lab.TOP1000_IN_RANGES
        assert 2200 <= data.server_ssh_port <= 2299 and 40001 <= data.server_high_port <= 49150
        assert len(data.communities) == 40 and data.printer_community in data.communities
        assert 'public' not in data.communities and 'private' not in data.communities
        assert data.ssh_private_key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----')
        assert data.ssh_public_key.startswith('ssh-ed25519 ')
        assert data.server_cn in data.server_cert or data.server_cert.startswith('-----BEGIN CERTIFICATE-----')

    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        machines = {m.name for m in ns.get_machines()}
        assert machines == {'attacker', 'probe', 'gw', 'desk', 'printer', 'nas', 'server', 'camera', 'legacy', 'db',
                            'www', 'app', 'admin'}
        hidden = {name for name, spec in lab.NetScheme._machine_specs.items() if spec.get('hidden')}
        assert hidden == {'probe', 'desk', 'printer', 'nas', 'server', 'camera'}
        assert all(lab.NetScheme._machine_specs[m].get('entrypoint') == '/sbin/init' for m in ('legacy', 'db', 'www', 'app'))
        assert not any(spec.get('bridged') for spec in lab.NetScheme._machine_specs.values())

    def test_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops, _ = ns.compute_state_ops('initial')
        text = json.dumps(ops, default=lambda op: getattr(op, 'filename', str(op)))
        for needle in ('/etc/sre-nas.nft', 'vsftpd /etc/vsftpd.conf', f'sshd -p {data.server_ssh_port}',
                       'systemctl enable --now ssh vsftpd inetd rsync tftpd-hpa', lab.WORDLIST, lab.ASSET_SERVICE):
            assert needle in text, needle
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
        assert lab.nft_conf_drops_input(lab.render_app_nftables(data))
        assert not lab.nft_conf_drops_input("table inet filter {\n chain input {\n type filter hook input priority 0;\n"
                                            " # policy drop;\n }\n}\n")
        assert str(data.nets.mgmt) in lab.render_app_nftables(data)
        algos = {}
        for line in lab.SSH_HARDENED.splitlines():
            key, _, value = line.partition(' ')
            algos[key] = value.split(',')
        weak = nmap_scan.weak_ssh_algorithms({'kex_algorithms': algos['KexAlgorithms'],
                                              'encryption_algorithms': algos['Ciphers'],
                                              'mac_algorithms': algos['MACs'],
                                              'server_host_key_algorithms': algos['HostKeyAlgorithms']})
        assert weak == {'kex': [], 'cipher': [], 'mac': [], 'host_key': []}
        assert 'server_tokens' not in lab.NGINX_WWW_HARDENED and 'TLSv1.2 TLSv1.3' in lab.NGINX_WWW_HARDENED
        assert 'serial: ' in lab.NSE_REFERENCE and 'categories = {"discovery", "safe"}' in lab.NSE_REFERENCE
        assert f"requirepass {data.redis_password}" in ns.redis_cmd()
        assert f"rocommunity {data.snmp_secret} {data.nets.mgmt}" in ns.snmpd_hardened()

    def test_helpers(self, lab):
        assert lab._ports_answer("22, 80 443/tcp;53") == {22, 80, 443, 53}
        assert lab._ports_answer("22, ssh") == set()
        assert lab._not_enabled('disabled') and lab._not_enabled('masked') and lab._not_enabled('')
        assert not lab._not_enabled('enabled') and not lab._not_enabled('alias')

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|reseau|sonde|serveur|attaquant|partie|imprimante|pare_feu|etat|mot_de_passe)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()] + list(vars(data.ips)) + list(vars(data.nets))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        fields = [f for q in grade.get_questions_ordered() for f in form_spec.form_fields(_text(q.description))]
        names += [f['name'] for f in fields] + [c for f in fields for c in f.get('choices', [])]
        assert 'final' in names and 'part9_firewall' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _instructor_literals():
    ast = check_sre_translations.ast
    literals = []
    for node in ast.walk(ast.parse(_LAB_PATH.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'instructor':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'id', '') == 'tr' and sub.args \
                        and isinstance(sub.args[0], ast.Constant):
                    literals.append(sub.args[0].value)
    return literals


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
            'why', 'discovery', 'tcp', 'udp', 'versions', 'output', 'nse', 'nse-write', 'surface', 'bind', 'ssh',
            'web', 'firewall', 'verify', 'memo']
        text = _text(course)
        assert '@@' not in text
        # no value of the instance and no summary of the questions in the course
        for value in (str(data.nets.office.network_address), str(data.ips.www.ip), data.redis_password,
                      data.snmp_secret, data.printer_community, data.server_cn, 'Partie 1', 'SRE-ASSET'):
            assert value not in text, value

    def test_translations(self, lab):
        """Every text is French with its English in _TRANSLATIONS['en'] (the markup kept: checked for every lab
        of the directory by test_draft_misc_translations.py), the 19 instructor texts among them."""
        tree = check_sre_translations.ast.parse(_LAB_PATH.read_text())
        tr_strings = check_sre_translations.get_tr_strings(tree)
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == set(tr_strings) and all(english.values())
        literals = _instructor_literals()
        assert len(literals) == len(set(literals)) == INSTRUCTOR_TEXTS and set(literals) <= set(english)
        assert all(english[k] != k for k in english)
        assert lab.title.resolve('en') == "Scanning and hardening: nmap, NSE scripts and attack surface reduction"
        assert lab.NetScheme.final._sre_state_description.resolve('en').startswith("Complete reference solution")
        for fr, en in english.items():
            assert set(re.findall(r'\{(\w+)\}', fr)) == set(re.findall(r'\{(\w+)\}', en)), fr[:60]

    def test_fragments_in_both_languages(self, lab, data, tmp_pub_dir):
        _, _, grade = _texts(lab, data, tmp_pub_dir)
        questions = grade.get_questions_ordered()
        assert len(questions) == 20
        with_fields = [q for q in questions if form_spec.form_fields(_text(q.description))]
        assert len(with_fields) == 9
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
        assert result.calls == 16 and result.translations == INSTRUCTOR_TEXTS
        for text in (b'**Solution', b"Pour l'enseignant", b'For the instructor'):
            assert text not in result.data
        stripped = tmp_path / 'scan_hardening_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('scan_hardening_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - INSTRUCTOR_TEXTS
        grade = _replay(module, _evaluation('final'), answers='final')
        assert _totals(grade) == (TOTAL, TOTAL, 6)
