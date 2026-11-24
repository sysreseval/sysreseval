"""Offline tests of the Ansible automation lab (lab/sre/_DRAFT_misc/ansible.py).

No Docker: the grading is replayed on a real project captured live on s16 (2026-11-23,
tests/mock_data/ansible/ansible_live.json): its ``data.json``, every test output of an evaluation
of the untouched project and of an evaluation right after the ``final`` state.  A model mixes the
two, part by part: a command belonging to a part that is "done" gets the output of the final
evaluation, any other the untouched output; the trace of the ansible-playbook runs keeps the runs
of the playbooks of the parts done, and the configuration dump the settings of the parts done.
The registered commands must be exactly those of the capture: a change to a command of the grader
needs a new capture (live).  Covers the data, the topology, the states, the two-pass grading
contract (nothing done: 0; everything: 95 + 6 bonus points; **each part alone gives exactly its
points and everything but one part the rest**) and the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from ansible_helpers import parse_runs  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'ansible.py'
LIVE = json.loads((_REPO / 'tests' / 'mock_data' / 'ansible' / 'ansible_live.json').read_text())

PARTS = ('access', 'users', 'role', 'loadbalancer', 'vault', 'router', 'bonus')
POINTS = {'access': 18, 'users': 18, 'role': 19, 'loadbalancer': 12, 'vault': 12, 'router': 16, 'bonus': 6}
#: the playbook of each part in the trace
PLAYBOOK_PART = {'users.yml': 'users', 'web.yml': 'role', 'lb.yml': 'loadbalancer', 'secrets.yml': 'vault',
                 'gw.yml': 'router', 'report.yml': 'bonus'}
#: the settings of `ansible-config dump` of each part
CONFIG_PART = {'DEFAULT_VAULT_PASSWORD_FILE': 'vault'}
#: the state whose cheat answers fill the forms of a part
FORM_STATES = {'access': 'solve_access', 'role': 'solve_web'}
CHOICE_ELEMENTS = {'q_config', 'q_handlers'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ansible_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.from_dict(LIVE['data']['data'])     # data.json: {'__type__': 'Data', 'data': {...}}
    d.compute_post_generate()
    return d


@pytest.fixture(scope='module')
def fresh(lab):
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
    if hasattr(ns, 'remount_proc_sys_done'):
        del ns.remount_proc_sys_done
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
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


# ---------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------


def part_of(lab, machine, cmd):
    """The part a registered command belongs to (TRACE / CONFIG: mixed by line)."""
    if 'ansible-runs.jsonl' in cmd:
        return 'TRACE'
    if 'ansible-config dump' in cmd:
        return 'CONFIG'
    if 'ansible-inventory' in cmd or 'SSH_KEY_OK' in cmd:
        return 'access'
    if f'roles/{lab.ROLE}' in cmd:
        return 'role'
    if "--include='*.j2'" in cmd:
        return 'loadbalancer'
    if 'libcrypt' in cmd or 'vault' in cmd or (machine == 'control' and 'grep -rlF' in cmd):
        return 'vault'
    if lab.REPORT in cmd:
        return 'bonus'
    if machine in lab.NODES and any(x in cmd for x in ('/etc/motd', 'getent', 'authorized_keys', 'sudoers', 'HOME_')):
        return 'users'
    if 'sre_lb_syn' in cmd or machine == 'lb' or (machine == 'control' and 'http_code' in cmd):
        return 'loadbalancer'
    if machine in lab.WEBS:
        return 'role'
    if machine in ('gw', 'client') or (machine == 'control' and ('ping' in cmd or '/dev/tcp' in cmd)):
        return 'router'
    raise AssertionError(f"no part for {machine}: {cmd}")


class World:
    def __init__(self, lab, done):
        self.lab, self.done = lab, set(done)
        self.outputs = {label: {(m, s, c): (o, code) for m, s, c, o, code in LIVE[label]}
                        for label in ('untouched', 'final')}

    def output(self, machine, command, step):
        key = (machine, step, command)
        assert key in self.outputs['final'], f"command not in the capture: {machine} step {step}: {command}"
        part = part_of(self.lab, machine, command)
        final, untouched = self.outputs['final'][key], self.outputs['untouched'][key]
        if part == 'TRACE':
            lines = [line for line in final[0].splitlines() if line.strip()
                     and PLAYBOOK_PART[Path(json.loads(line)['playbook']).name] in self.done]
            return "".join(line + "\n" for line in lines), 0
        if part == 'CONFIG':
            if 'access' not in self.done and 'vault' not in self.done:
                return untouched
            keep = []
            for line in final[0].splitlines():
                key_name = line.split('(', 1)[0]
                owner = CONFIG_PART.get(key_name, 'access')
                if not re.match(r'^[A-Z_]+\(', line) or owner in self.done or (
                        key_name == 'CONFIG_FILE'):
                    keep.append(line)
            return "\n".join(keep) + "\n", final[1]
        return final if part in self.done else untouched


def _simulate(lab, data, done=PARTS, instructor_mode=False, answers=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    model = World(lab, done)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            merged = {}
            if answers:
                for part, state in FORM_STATES.items():
                    if part in done:
                        merged.update(grade.get_cheat_answers(state) or {})
            grade._answers = merged
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = model.output(m, key[0], s)
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus))


def _parts(grade):
    result = {str(p.title): 0 for p in grade.get_grade_parts()}
    for e in grade.get_grade_list():
        result[str(e.grade_part)] += e.grade
    return result


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, fresh):
        assert lab.Data.from_dict(fresh.to_dict()).to_dict() == fresh.to_dict()

    def test_values(self, lab, fresh):
        d = fresh
        assert d.company in lab.COMPANIES and 8001 <= d.http_port <= 8999 and d.http_port not in (8080, 8443)
        assert set(d.serials) == set(lab.NODES) == set(d.racks) and len(set(d.serials.values())) == 4
        assert all(re.fullmatch(r'SN-\d{6}', s) for s in d.serials.values())
        assert len(d.admins) == 3 and len({a['name'] for a in d.admins}) == 3 and len({a['uid'] for a in d.admins}) == 3
        assert all(a['key'].startswith('ssh-ed25519 ') and a['key'].endswith(f"{a['name']}@{d.company}")
                   for a in d.admins)
        assert d.old_account in lab.OLD_ACCOUNTS and d.old_account not in {a['name'] for a in d.admins}
        assert d.ref_private_key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----')
        assert d.ref_public_key.startswith('ssh-ed25519 ') and d.ref_public_key.endswith(' root@control')
        assert len({d.ansible_password, d.vault_password, d.archiver_password}) == 3
        assert all(p.isalnum() for p in (d.ansible_password, d.vault_password, d.archiver_password))
        assert d.nets.mgmt != d.nets.ext and d.nets.mgmt.prefixlen == d.nets.ext.prefixlen == 24
        assert str(d.ips.gw.ip).endswith('.1') and str(d.ips.lb.ip).endswith('.20') and d.ips.client.ip in d.nets.ext
        assert d.site_name == f"Intranet {d.company.capitalize()}" and d.motd.startswith(d.company.upper() + ':')

    def test_topology(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'control', 'web1', 'web2', 'lb', 'gw', 'client'}
        specs = lab.NetScheme._machine_specs
        assert all(specs[m]['privileged'] and specs[m]['entrypoint'] == '/sbin/init' for m in lab.NODES)
        assert specs['control']['image'].split('/')[-1].startswith('ansible:')
        assert ns.net_config['gw'] == [([fresh.ips.gw], []), ([fresh.ips.gw_ext], [])]
        assert ns.get_weight() == 4 * 12 + 2


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for m in lab.NODES:
            files = _files(ops, 1, m)
            assert json.loads(files[lab.FACT_FILE]) == {'serial': fresh.serials[m], 'rack': fresh.racks[m],
                                                        'owner': fresh.company}
            assert files['/etc/sudoers.d/ansible'] == "ansible ALL=(ALL) NOPASSWD: ALL\n"
            cmds = _cmds(ops, 1, m)
            assert 'systemctl start ssh' in cmds and 'sysctl -w net.ipv4.ip_forward=0' in cmds
            assert any(fresh.old_account in c and 'useradd' in c for c in cmds)
        files = _files(ops, 1, 'control')
        assert files['/usr/share/ansible/plugins/callback/sre_trace.py'] == (_REPO / 'lib' / 'ansible_trace.py').read_text()
        assert {f"/root/ansible/files/keys/{a['name']}.pub": a['key'] + "\n" for a in fresh.admins}.items() <= files.items()
        assert files['/etc/hosts'] == "127.0.0.1\tlocalhost\n127.0.1.1\tcontrol\n"

    def test_solve_states_write_the_reference_project(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        expected = {
            'solve_access': ({'inventory.ini'}, []),
            'solve_users': ({'users.yml'}, ['users.yml']),
            'solve_web': ({'web.yml', 'group_vars/webservers.yml', 'roles/webserver/tasks/main.yml',
                           'roles/webserver/handlers/main.yml', 'roles/webserver/defaults/main.yml',
                           'roles/webserver/templates/site.conf.j2', 'roles/webserver/templates/index.html.j2'},
                          ['web.yml', 'web.yml']),
            'solve_lb': ({'lb.yml', 'templates/lb.conf.j2', 'group_vars/webservers.yml'}, ['lb.yml']),
            'solve_vault': ({'secrets.yml', 'vars/vault.yml', '.vault_pass'}, ['secrets.yml']),
            'solve_gw': ({'gw.yml', 'templates/nftables.conf.j2', 'host_vars/gw.yml'}, ['gw.yml']),
            'solve_bonus': ({'report.yml', 'templates/report.md.j2'}, ['report.yml']),
        }
        for state, (paths, books) in expected.items():
            ops = _state_ops(ns, state)
            files = {p[len('/root/ansible/'):] for p in _files(ops, 1, 'control') if p.startswith('/root/ansible/')}
            assert files == paths, state
            plays = [c.split()[-1] for c in _cmds(ops, 3, 'control') if 'ansible-playbook' in c]
            assert plays == books, state
            if state != 'solve_access':
                assert all(f"-i {lab.REF_INVENTORY}" in c for c in _cmds(ops, 3, 'control'))
                assert lab.REF_INVENTORY in _files(ops, 1, 'control')
                assert '/root/.ssh/id_ed25519' not in _files(ops, 1, 'control')
        final = _state_ops(ns, 'final')
        plays = [c.split()[-1] for c in _cmds(final, 3, 'control') if 'ansible-playbook' in c]
        assert plays == ['users.yml', 'web.yml', 'lb.yml', 'secrets.yml', 'gw.yml', 'report.yml', 'web.yml']
        step2 = _cmds(final, 2, 'control')
        assert step2[-1] == "cd /root/ansible && ansible-vault encrypt vars/vault.yml"
        assert any('vault_password_file = .vault_pass' in c for c in step2)
        assert any('inventory = inventory.ini' in c for c in step2)
        assert all(fresh.ref_public_key.split()[1] in ' '.join(_cmds(final, 2, m)) for m in lab.NODES)

    def test_reference_files(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        inv = ns.inventory_ini()
        assert f"web1 ansible_host={fresh.ips.web1.ip}" in inv and "[production:children]\nwebservers\nloadbalancers" in inv
        assert 'ansible_password' not in inv and f"ansible_password={fresh.ansible_password}" in ns.inventory_ini(True)
        users = ns.users_yml()
        assert all(f"{{ name: {a['name']}, uid: {a['uid']} }}" in users for a in fresh.admins)
        assert 'validate: /usr/sbin/visudo -cf %s' in users and 'loop: "{{ admins }}"' in users
        assert "groups['webservers']" in ns.lb_conf_j2() and 'hostvars[host]' in ns.lb_conf_j2()
        assert 'no_log: true' in ns.secrets_yml() and 'vars/vault.yml' in ns.secrets_yml()
        assert 'validate: /usr/sbin/nft -c -f %s' in ns.gw_yml() and 'ansible.posix.sysctl' in ns.gw_yml()
        assert "['eth0']['ipv4']['address']" in ns.report_j2()
        assert 'delegate_to: localhost' in ns.report_yml() and 'run_once: true' in ns.report_yml()


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_capture_is_complete(self, lab, data, tmp_pub_dir):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        registered = {(m, s, c) for (m, s), cmds in grade.get_tests().items() for c, _t in cmds}
        assert registered == {(m, s, c) for m, s, c, _o, _code in LIVE['final']}

    def test_untouched(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, done=(), answers=False)
        assert _totals(grade) == (0, 0)

    def test_everything(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data)
        assert {t: g for t, g in _grades(grade).items() if g[0] != g[1]} == {}
        assert _totals(grade) == (95, 6)
        assert _parts(grade) == POINTS

    def test_points(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data)
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 95
        assert [str(e.title) for e in elements if e.bonus] == ['report_rows', 'report_delegated']
        assert {str(e.title) for e in elements if e.scope == params.EXO_EVAL_SCOPE} == CHOICE_ELEMENTS

    @pytest.mark.parametrize('part', PARTS)
    def test_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, done=(part,))
        assert _parts(grade) == {p: (POINTS[p] if p == part else 0) for p in PARTS}

    @pytest.mark.parametrize('part', PARTS)
    def test_all_but_one(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, done=tuple(p for p in PARTS if p != part))
        assert _parts(grade) == {p: (0 if p == part else POINTS[p]) for p in PARTS}

    def test_trace_elements_need_the_runs(self, lab, data, tmp_pub_dir, monkeypatch):
        """The node state of a configuration done by hand (no ansible-playbook run) scores without the
        elements that prove Ansible did it."""
        original = World.output

        def no_runs(self, machine, command, step):
            if 'ansible-runs.jsonl' in command:
                return '', 0
            return original(self, machine, command, step)

        monkeypatch.setattr(World, 'output', no_runs)
        grade, _ = _simulate(lab, data)
        lost = {t for t, (g, m) in _grades(grade).items() if g != m}
        assert lost == {'users_loop', 'role_structure', 'role_handler', 'role_idempotent', 'lb_template',
                        'gw_template_handler', 'report_delegated'}
        assert _grades(grade)['role_structure'] == (1, 2)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


class TestTexts:
    def test_course(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        from SRE.informations import resolve_informations
        resolved, _numbering = resolve_informations(ns.informations)      # (text, numbering)
        text = _text(resolved)
        assert '\n## <a id="why"></a>1. Pourquoi automatiser\n' in text      # the course itself, not a repr
        for word in ('ansible.cfg', 'inventaire', 'Vault', 'handler', 'delegate_to', 'Aide-mémoire'):
            assert word in text
        html = markdown_to_html(text)
        assert '```' not in html and '@@' not in html

    def test_questions_render(self, lab, data, tmp_pub_dir):
        for mode in (False, True):
            grade, _ = _simulate(lab, data, instructor_mode=mode)
            for q in grade.get_questions_ordered():
                for t in (q.title, q.description):
                    s = _text(t)
                    assert "{'" not in s and not re.search(r'\{[a-z_]+\}', s), s[:200]
                    html = markdown_to_html(s, show_instructor=mode)
                    assert '```' not in html
            texts = [_text(q.description) for q in grade.get_questions_ordered()]
            assert sum(has_instructor(t) for t in texts) == (11 if mode else 0)

    def test_values_in_texts(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, instructor_mode=True)
        text = "\n".join(_text(q.description) for q in grade.get_questions_ordered())
        for value in (data.ansible_password, data.vault_password, data.archiver_password, data.motd, data.site_name,
                      str(data.http_port), data.old_account, str(data.ops_gid), *data.serials.values()):
            assert value in text

    def test_form_fields(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data)
        names = [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', None) or []]
        assert names == ['serial_web1', 'serial_web2', 'serial_lb', 'serial_gw', 'which', 'merged', 'when', 'ok']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 11 and result.warnings == []
        assert b'**Solution' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'ansible_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('ansible_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, instructor_mode=True)
        assert _totals(grade) == (95, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, fresh, tmp_pub_dir):
        french = re.compile(r'(?:^|[_.:-])(routeur|reseau|partie|adresse|serveur|compte|cle|groupe|pare|'
                            r'mot_de_passe|nom|noeud)(?:$|[_.:-])', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        names += [f.name for f in fresh.__dataclass_fields__.values()]
        names += list(vars(fresh.ips)) + list(vars(fresh.nets))
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', None) or []]
        names += [c for q in grade.get_questions_ordered() for f in getattr(q, 'fields', None) or []
                  for c in f.get('choices', [])]
        assert 'initial' in names and 'final' in names and 'solve_vault' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []

    def test_trace_of_the_capture(self):
        runs = parse_runs([r for r in LIVE['final'] if 'ansible-runs.jsonl' in r[2]][0][3])
        assert [Path(r['playbook']).name for r in runs] == ['users.yml', 'web.yml', 'lb.yml', 'secrets.yml',
                                                            'gw.yml', 'report.yml', 'web.yml']
