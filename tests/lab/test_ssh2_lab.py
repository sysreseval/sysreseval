"""Offline tests of the SSH 2 lab (lab/sre/_DRAFT_misc/ssh2.py): the data (keys, ports, secrets), the
topology and the names each machine knows, the state ops (``initial``, the ``solve_*`` states and
``final``, every command on one line), the multi-pass grading contract, the instructor texts, the
numbered course, the stripped lab file and the English identifiers.

The archives of tests/mock_data/ssh2/lab/ are real evaluations of running projects (s15, 2026-11-25):
TestRealEvaluations replays what the grader's commands really printed (an untouched project, the
reference solution twice, two projects where only some parts were solved, one of them before the
solution created ``~admin/.ssh``), and changes one output at a time to check that each element is
graded on what it claims.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.archive_summary import read_archive
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import ssh as ssh_lib  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'ssh2.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'ssh2' / 'lab'
PARTS = {'part1': 14, 'part2': 10, 'part3': 8, 'part4': 7, 'part5': 11, 'part6': 10, 'part7': 12, 'bonus': 6}
TOTAL, BONUS = 72, 6
FORM_ELEMENTS = {'answer_vault_secret': 2, 'answer_intranet_secret': 1, 'answer_intranet_client': 1,
                 'answer_db_secret': 1, 'answer_db_client': 1, 'answer_loopback': 1, 'answer_wiki_secret': 1,
                 'answer_git_secret': 1, 'answer_curl_option': 1}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ssh2_lab_under_test', _LAB_PATH)
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
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if hasattr(op, 'filename') and hasattr(op, 'permissions')
            and type(op).__name__ == '_FileOp'}


def _op_signature(op):
    if isinstance(op, str):
        return ('cmd', str(op))
    content = op.content.decode() if isinstance(getattr(op, 'content', b''), bytes) else getattr(op, 'content', '')
    return (type(op).__name__, getattr(op, 'filename', ''), content)


def _set_marker(instructor_mode):
    marker = Path(params.instructor_mode_marker_filename(_running_name()))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()


def _run(lab, data, answers, respond, instructor_mode=False):
    """Multi-pass grade() like run_tests(): answers loaded before the first pass, every command
    of a step answered by respond(machine, command) (None: left at its placeholder), the registered
    tests never changing from one pass to the next."""
    _set_marker(instructor_mode)
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade._answers = dict(answers)
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        assert previous is None or current == previous, "the registered tests changed between two passes"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    result = respond(m, key[0])
                    if result is not None:
                        cmds[key] = result
        step += 1
    return grade, ns


def _archive(tag):
    return read_archive(str(_ARCHIVES / f"{tag}.zst"))


def _archive_data(lab, raw):
    stored = json.loads(raw['data_json'])
    stored['__type__'] = f"{lab.__name__}.Data"
    return lab.Data.from_json(json.dumps(stored))


def _replay(lab, tag, answers=True, mutate=None):
    """The evaluation recorded in tests/mock_data/ssh2/lab/<tag>.zst graded again by the current lab
    file; *mutate(machine, command, (out, code))* may change an output."""
    raw = _archive(tag)
    data = _archive_data(lab, raw)
    recorded = {}
    for (m, _s), cmds in raw['tests'].items():
        for (cmd, _timeout), result in cmds.items():
            recorded[(m, cmd)] = tuple(result)

    def respond(machine, command):
        result = recorded.get((machine, command))
        assert result is not None, f"not in the archive {tag!r}: {machine}: {command[:140]}"
        return mutate(machine, command, result) if mutate else result

    grade, _ = _run(lab, data, (raw.get('answers') or {}) if answers else {}, respond)
    return grade, data


def _totals(grade):
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.max_grade for e in elements if not e.bonus),
            sum(e.grade for e in elements if e.bonus))


def _by_part(grade):
    totals = {}
    for e in grade.get_grade_list():
        totals[str(e.grade_part)] = totals.get(str(e.grade_part), 0) + e.grade
    return totals


def _missing(grade):
    return sorted(str(e.title) for e in grade.get_grade_list() if e.grade != e.max_grade)


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


# ---------------------------------------------------------------------------
# data, topology, states
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        again = lab.Data.from_json(data.to_json())
        assert again.to_json() == data.to_json()

    def test_values(self, lab):
        for _ in range(50):
            d = lab.Data.generate()
            assert 18000 <= d.port_intranet <= 18999 and 19000 <= d.port_db <= 19999
            assert 11000 <= d.port_socks <= 11999 and 30000 <= d.port_relay <= 30999
            assert d.principal in lab.PRINCIPALS
            secrets_ = [d.secret_vault, d.secret_intranet, d.secret_db, d.secret_wiki, d.secret_git, d.secret_nas]
            assert len(set(secrets_)) == 6 and all(re.fullmatch(r'[a-z]+-[0-9a-f]{6}', s) for s in secrets_)
            pubs = [d.backup_pub, d.intern_pub, d.ref_admin_pub, d.ref_deploy_pub, d.ref_host_ca_pub,
                    d.ref_user_ca_pub]
            assert len({ssh_lib.public_key_fingerprint(p) for p in pubs}) == 6
            assert all(p.startswith('ssh-ed25519 AAAA') for p in pubs)
            assert d.backup_key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----')

    def test_addresses(self, lab, data):
        nets = [data.nets.internet, data.nets.corp, data.nets.secure, data.nets.home]
        assert len(set(nets)) == 4
        assert data.ips.bastion_inet in data.nets.internet and data.ips.bastion_corp in data.nets.corp
        assert data.ips.ops_corp in data.nets.corp and data.ips.ops_secure in data.nets.secure
        assert data.ips.nas in data.nets.home and data.ips.probe in data.nets.internet


class TestTopology:
    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert len(specs) == 11
        terminals = {m for m, s in specs.items() if s.get('allow_connection', True) and not s.get('hidden')}
        assert terminals == {'laptop', 'nas'}
        assert specs['laptop']['shell'] == specs['nas']['shell'] == lab.LOGIN_SHELL
        assert specs['probe']['hidden'] and not lab.export_kathara_project
        assert not any('image' in s for s in specs.values())       # the default image: base13

    def test_networks(self, lab):
        topo = lab.NetScheme._topology
        assert set(topo['corp']) == {'bastion', 'intranet', 'db', 'ops'}
        assert set(topo['secure']) == {'ops', 'vault'} and set(topo['home']) == {'homegw', 'nas'}
        assert 'probe' in topo['internet'] and 'laptop' in topo['internet']

    def test_names_known_by_each_machine(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        laptop = ns.hosts_content('laptop')
        assert 'bastion.example.net' in laptop and 'corp.lan' not in laptop
        bastion = ns.hosts_content('bastion')
        assert 'ops.corp.lan' in bastion and 'wiki.corp.lan' in bastion and 'vault' not in bastion
        assert f"{data.ip('ops_secure')}\tvault" not in ns.hosts_content('ops')
        assert 'vault.corp.lan' in ns.hosts_content('ops')
        vault = ns.hosts_content('vault')
        assert f"{data.ip('ops_secure')}\tops.corp.lan" in vault and 'bastion' not in vault
        assert 'relay.example.net' in ns.hosts_content('nas') and 'corp.lan' not in ns.hosts_content('nas')


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        assert set(m for _s, m in ops) == set(lab.NetScheme._machine_specs)
        assert _files(ops, 1, 'ops')['/etc/ssh/sshd_config.d/50-hardening.conf'].count('AllowTcpForwarding no') == 1
        assert data.secret_intranet in _files(ops, 1, 'intranet')['/etc/nginx/sites-enabled/intranet']
        assert data.secret_wiki in _files(ops, 1, 'intranet')['/etc/nginx/sites-enabled/intranet']
        assert f"listen 127.0.0.1:{lab.DB_CONSOLE_PORT}" in _files(ops, 1, 'db')['/etc/nginx/sites-enabled/db']
        assert data.secret_nas in _files(ops, 1, 'nas')['/etc/nginx/sites-enabled/nas']
        assert _files(ops, 1, 'vault')['/home/sysop/secret'].strip() == data.secret_vault
        assert _files(ops, 1, 'laptop')[lab.BACKUP_KEY] == data.backup_key
        assert _files(ops, 1, 'laptop')[lab.INTERN_KEY + '.pub'].strip() == data.intern_pub
        assert data.upload_password in _files(ops, 1, 'probe')[lab.PROBE_ASKPASS]
        for m in lab.NetScheme._machine_specs:
            assert any('mkdir -p /run/systemd/system' in c and 'ssh-keygen -A' in c for c in _cmds(ops, 1, m))
            # the daemons start once every file is written
            assert any('systemctl start ssh' in c for c in _cmds(ops, 2, m))
            assert not any('systemctl start ssh' in c for c in _cmds(ops, 1, m))
        assert any('masquerade' in c for c in _cmds(ops, 1, 'homegw'))
        for m in lab.SUDO_MACHINES:
            assert '/etc/sudoers.d/sysop' in _files(ops, 1, m)
        assert '/etc/sudoers.d/sysop' not in _files(ops, 1, 'vault')

    @pytest.mark.parametrize('state', ['initial', 'final', 'solve_part1', 'solve_part2', 'solve_part3',
                                       'solve_part4', 'solve_part5', 'solve_part6', 'solve_part7', 'solve_bonus'])
    def test_commands_are_single_lines(self, lab, data, state):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, state)
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert '\n' not in str(op) and '@@@' not in str(op), (state, m, str(op)[:80])

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = {k: [_op_signature(op) for op in v] for k, v in _state_ops(ns, 'final').items()}
        for part in ('part1', 'part2', 'part3', 'part4', 'part5', 'part6', 'part7', 'bonus'):
            for key, op_list in _state_ops(ns, f'solve_{part}').items():
                for op in op_list:
                    assert _op_signature(op) in final[key], (part, key, _op_signature(op)[:2])

    def test_reference_files(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        laptop = _files(ops, 1, 'laptop')
        assert 'ProxyJump ops' in laptop['/home/admin/.ssh/config.d/part1.conf']
        assert 'ControlPersist yes' in laptop['/home/admin/.ssh/config.d/bonus.conf']
        assert laptop[lab.HOST_CA] == data.ref_host_ca and laptop[lab.USER_CA] == data.ref_user_ca
        files = _files(ops, 1, 'files')
        assert files['/home/backupbot/.ssh/authorized_keys'].startswith(f'from="{data.ip("laptop")}",restrict,')
        assert 'ChrootDirectory /srv/sftp/%u' in files['/etc/ssh/sshd_config.d/90-sftp-upload.conf']
        assert _files(ops, 1, 'bastion')['/etc/ssh/auth_principals/deploy'].strip() == data.principal
        assert any('kill -HUP' in c for c in _cmds(ops, 1, 'bastion'))
        assert any('ssh-keygen -k -f /etc/ssh/revoked_keys' in c for c in _cmds(ops, 1, 'bastion'))
        # the directory of known_hosts exists before the append of the CA line
        laptop_ops = [_op_signature(op) for op in ops[(1, 'laptop')]]
        mkdir = laptop_ops.index(('cmd', 'install -d -m 700 -o admin -g admin /home/admin/.ssh'))
        append = next(i for i, op in enumerate(laptop_ops) if op[1] == '/home/admin/.ssh/known_hosts')
        assert mkdir < append


# ---------------------------------------------------------------------------
# grading contract and texts
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_answered(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        assert _totals(grade) == (0, TOTAL, 0)
        parts = {}
        for e in grade.get_grade_list():
            parts[str(e.grade_part)] = parts.get(str(e.grade_part), 0) + e.max_grade
            assert e.bonus == (str(e.grade_part) == 'bonus')
        assert parts == PARTS

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        final = dict(grade.get_cheat_answers('final') or {})
        grade, _ = _run(lab, data, final, lambda m, c: None)
        got = {str(e.title): e.grade for e in grade.get_grade_list() if e.grade}
        assert got == FORM_ELEMENTS
        for part in ('part1', 'part2', 'part3', 'part4'):
            assert grade.get_cheat_answers(f'solve_{part}')

    def test_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, _ = _run(lab, data, {}, lambda m, c: None)
        final = dict(grade.get_cheat_answers('final') or {})
        hashes = {next(f['name'] for f in q.fields): q.question_hash
                  for q in grade.get_questions_ordered() if getattr(q, 'fields', None)}
        loopback = hashes['loopback']
        curl = hashes['wiki_secret']
        for value, ok in (('localhost', 1), (' 127.0.0.1 ', 1), ('0.0.0.0', 0)):
            answers = dict(final)
            answers[loopback] = json.dumps({**json.loads(final[loopback]), 'loopback': value})
            g, _ = _run(lab, data, answers, lambda m, c: None)
            assert {str(e.title): e.grade for e in g.get_grade_list()}['answer_loopback'] == ok
        for value, ok in (('socks5h://', 1), ('curl --socks5-hostname', 1), ('--socks5', 0)):
            answers = dict(final)
            answers[curl] = json.dumps({**json.loads(final[curl]), 'curl_option': value})
            g, _ = _run(lab, data, answers, lambda m, c: None)
            assert {str(e.title): e.grade for e in g.get_grade_list()}['answer_curl_option'] == ok


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _run(lab, data, {}, lambda m, c: None, instructor_mode=False)
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        hashes = [q.question_hash for q in g0.get_questions_ordered()]
        assert hashes == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(hashes) == 9 and len(set(hashes)) == 9 and all(re.fullmatch(r'[0-9a-f]{16}', h) for h in hashes)
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        assert len([w for w, t in _all_texts(g1, ns1) if has_instructor(t)]) == 9
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        for value in (data.sysop_password, data.upload_password, data.principal, str(data.port_relay),
                      data.ip('laptop')):
            assert value in student
        for secret in (data.secret_vault, data.secret_intranet, data.secret_db, data.secret_wiki, data.root_password):
            assert secret not in student

    def test_texts_are_formatted_and_render(self, lab, data, tmp_pub_dir):
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            plain = re.sub(r"```.*?```", "", re.sub(r"@@\{[^}]*\}@@", "", text), flags=re.S)
            assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", plain), where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)

    def test_course_is_numbered_and_generic(self, lab, data, tmp_pub_dir):
        g1, ns1 = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        resolved, numbering = resolve_informations(ns1.informations)
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 18)]
        informations = _text(resolved)
        assert not re.search(r'@@(sec|ref|tag|toc)', informations)
        other = lab.Data.generate()
        other.compute_post_generate()
        assert _text(lab.NetScheme(data=other, running_lab_name=_running_name()).informations) == \
            _text(ns1.informations)
        assert not re.search(r"^ +```", _text(ns1.informations), re.M)
        for q in g1.get_questions_ordered():
            assert '@@ref' not in resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering).resolve('fr')

    def test_course_examples_stay_outside_the_draws(self, lab):
        # the numbers written in the course are never values of an instance
        ns_text = None
        for _ in range(200):
            d = lab.Data.generate()
            d.compute_post_generate()
            if ns_text is None:
                ns_text = _text(lab.NetScheme(data=d, running_lab_name=_running_name()).informations)
            for port in (d.port_intranet, d.port_db, d.port_socks, d.port_relay):
                assert not re.search(rf'(?<![0-9]){port}(?![0-9])', ns_text)

    def test_form_fields(self, lab, data, tmp_pub_dir):
        g1, _ = _run(lab, data, {}, lambda m, c: None, instructor_mode=True)
        fields = [f['name'] for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        assert fields == ['vault_secret', 'intranet_secret', 'intranet_client', 'db_secret', 'db_client', 'loopback',
                          'wiki_secret', 'git_secret', 'curl_option']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 9 and result.warnings == []
        stripped = tmp_path / 'ssh2_stripped.py'
        stripped.write_bytes(result.data)
        assert b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('ssh2_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _run(module, data, {}, lambda m, c: None, instructor_mode=True)
        assert _totals(grade) == (0, TOTAL, 0)

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(serveur|machine_|cle_|clef|secret_de|tunnel_local|sonde|fichier|passerelle|'
                            r'certificat|compte|mot_de_passe)', re.I)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [f for f in data.__dataclass_fields__] + list(vars(data.ips)) + list(vars(data.nets))
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad


# ---------------------------------------------------------------------------
# real evaluations replayed
# ---------------------------------------------------------------------------


def _when(predicate, change):
    def mutate(machine, command, result):
        return change(result) if predicate(machine, command) else result
    return mutate


def _replace(output):
    return lambda result: (output, result[1])


def _drop(fragment):
    """Remove the lines holding *fragment* from an output."""
    def change(result):
        out, code = result
        return "\n".join(line for line in out.splitlines() if fragment not in line) + "\n", code
    return change


def _sub(old, new):
    def change(result):
        out, code = result
        assert old in out, old
        return out.replace(old, new), code
    return change


def _resub(pattern, repl):
    def change(result):
        out, code = result
        new = re.sub(pattern, repl, out)
        assert new != out, pattern
        return new, code
    return change


def _on(machine, fragment):
    return lambda m, c: m == machine and fragment in c


class TestRealEvaluations:
    """What running projects really answered (s15, 2026-11-25): tests/mock_data/ssh2/lab/*.zst."""

    def test_untouched_project(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'initial')
        assert _totals(grade) == (0, TOTAL, 0)

    @pytest.mark.parametrize('tag', ['final', 'final_again'])
    def test_full_marks(self, lab, tmp_pub_dir, tag):
        grade, _ = _replay(lab, tag)
        assert _missing(grade) == [] and _by_part(grade) == PARTS and _totals(grade) == (TOTAL, TOTAL, BONUS)

    def test_some_parts_alone(self, lab, tmp_pub_dir):
        # parts 2, 4, 6 and the bonus; the reference keys of parts 2 / 4 count in part 1 (key made, on bastion)
        grade, _ = _replay(lab, 'parts_2_4_6_bonus')
        assert _by_part(grade) == {'part1': 2, 'part2': 10, 'part3': 0, 'part4': 7, 'part5': 0, 'part6': 10,
                                   'part7': 0, 'bonus': 6}
        grade, _ = _replay(lab, 'parts_3_5_7')
        assert _by_part(grade) == {'part1': 0, 'part2': 0, 'part3': 8, 'part4': 0, 'part5': 11, 'part6': 0,
                                   'part7': 12, 'bonus': 0}

    def test_no_certificate_authority_on_the_client(self, lab, tmp_pub_dir):
        # recorded before the solution created ~admin/.ssh: no @cert-authority line on laptop
        grade, _ = _replay(lab, 'parts_3_5_7_without_ssh_dir')
        assert [t for t in _missing(grade) if t.startswith(('bastion', 'relay'))] == ['bastion_trusted',
                                                                                    'relay_trusted']
        assert _by_part(grade)['part5'] == 7

    def test_typed_answers(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'final', answers=False)
        assert set(_missing(grade)) == set(FORM_ELEMENTS)
        assert _totals(grade) == (TOTAL - sum(FORM_ELEMENTS.values()), TOTAL, BONUS)

    @pytest.mark.parametrize('name, predicate, change, lost', [
        ('no ProxyJump for vault', _on('laptop', "ssh -G vault"), _drop('proxyjump'), {'config_vault'}),
        ('vault through bastion only', _on('laptop', "ssh -G vault"), _sub('proxyjump ops', 'proxyjump bastion'),
         {'config_vault'}),
        ('ops still refuses', _on('ops', 'sshd -T'), _sub('allowtcpforwarding yes', 'allowtcpforwarding no'),
         {'ops_forwarding'}),
        ('ops not reloaded', _on('ops', 'sshd -T'),
         lambda r: (r[0] + "==SRE-SSH== stale /etc/ssh/sshd_config.d/50-hardening.conf\n", r[1]), {'ops_forwarding'}),
        ('vault reached from elsewhere', _on('vault', 'auth.log'),
         _resub(r'(Accepted publickey for sysop from )\S+', r'\g<1>10.99.99.99'),
         {'vault_login'}),
        ('no key for admin', _on('laptop', 'id_ed25519.pub 2>/dev/null'), _replace(''),
         {'key_on_bastion', 'key_on_ops', 'key_on_vault'}),
        ('intranet tunnel closed', _on('laptop', 'ss -Hltne'), _drop('127.0.0.1:18'), {'tunnel_intranet'}),
        ('db console not answering', _on('laptop', 'http://127.0.0.1:19'), _replace(''), {'tunnel_db'}),
        ('relay not public', _on('probe', 'curl'), _replace(''), {'reverse_tunnel_public'}),
        ('GatewayPorts no', _on('relay', 'sshd -T'), _sub('gatewayports clientspecified', 'gatewayports no'),
         {'relay_gatewayports'}),
        ('socks proxy closed', _on('laptop', 'socks5-hostname'), _replace('curl: (7) Failed to connect\n'),
         {'socks_proxy'}),
        ('bastion presents no certificate', _on('probe', 'ssh-keyscan -c -t ed25519 -T 5 bastion'), _replace(''),
         {'bastion_host_cert_served'}),
        ('relay certificate without the full name', _on('relay', 'ssh-keygen -L'), _drop('relay.example.net'),
         {'relay_host_cert', 'relay_host_cert_served'}),
        ('bastion not trusted under its full name', _on('laptop', '@cert-authority'),
         _sub('nobody@bastion.example.net: Permission denied (publickey,password).',
              'Host key verification failed.'), {'bastion_trusted'}),
        ('deploy certificate for a year', _on('laptop', 'deploy-cert.pub'), _sub('to 2026-11-26', 'to 2027-11-26'),
         {'deploy_cert'}),
        ('deploy never logged in on relay', _on('relay', 'auth.log'), _drop('Accepted publickey for deploy'),
         {'deploy_login_relay'}),
        ('root may log in on files', _on('files', 'sshd -T'), _sub('permitrootlogin no', 'permitrootlogin yes'),
         {'files_no_root_login'}),
        ('no prison', _on('probe', 'sftp'), _sub('/incoming', '/incoming\n/etc'), {'sftp_chroot', 'sftp_upload'}),
        ('upload has a shell', _on('probe', ' id </dev/null'), _replace('uid=1004(upload) gid=1004(upload)\n'),
         {'upload_no_shell'}),
        ('backup key without restrict', _on('laptop', '-W 127.0.0.1:22'),
         _replace('SSH-2.0-OpenSSH_10.0p2 Debian'), {'backup_restricted'}),
        ('backup key not installed', _on('laptop', 'tar -tzf'), _replace('tar: Error is not recoverable\n'),
         {'backup_forced_command', 'backup_restricted', 'backup_from'}),
        ('backup key accepted from anywhere', _on('probe', 'backupbot'), _replace('\x1f\x8b'), {'backup_from'}),
        ('intern not revoked', _on('bastion', 'auth.log'), _drop('revoked by file'), {'intern_revoked'}),
        ('no master', _on('laptop', 'ssh -O check'),
         _replace('Control socket connect(/home/admin/.ssh/cm-x): No such file or directory\n==SRE-SSH2== rc=255\n'),
         {'mux_master'}),
    ])
    def test_one_output_changed(self, lab, tmp_pub_dir, name, predicate, change, lost):
        grade, _ = _replay(lab, 'final', mutate=_when(predicate, change))
        assert set(_missing(grade)) == lost, name
