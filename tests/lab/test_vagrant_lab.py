"""Offline tests of the Vagrant lab (lab/sre/_DRAFT_misc/vagrant.py).

No Docker: the grading is replayed on a real project captured live on s16 (2026-11-24,
tests/mock_data/vagrant/vagrant_live.json): its ``data.json``, every test output of an evaluation
of the untouched project and of an evaluation right after the ``final`` state.  A model mixes the
two, part by part: a command belonging to a part that is "done" gets the output of the final
evaluation, any other the untouched output; the outputs shared by every part are filtered: the
machines Vagrant recorded (by project), the containers of the inner daemon (by the ids of the
machines kept) and the files (by block).  The registered commands must be exactly those of the
capture: a change to a command of the grader needs a new capture (live).  Covers the data, the
topology, the states, the two-pass grading contract (nothing done: 0; everything: 87 + 12 bonus
points; **each part alone gives exactly its points and everything but one part the rest**) and the
texts.
"""
import ast
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Network
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from vagrant_helpers import parse_vagrant_machines  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'vagrant.py'
LIVE = json.loads((_REPO / 'tests' / 'mock_data' / 'vagrant' / 'vagrant_live.json').read_text())

PARTS = ('hello', 'web', 'cluster', 'provision', 'sync', 'kiosk', 'bonus_boxes', 'bonus_triggers', 'bonus_fleet')
POINTS = {'hello': 14, 'web': 15, 'cluster': 18, 'provision': 14, 'sync': 12, 'kiosk': 14,
          'bonus_boxes': 4, 'bonus_triggers': 4, 'bonus_fleet': 4}
BONUS = {'bonus_boxes', 'bonus_triggers', 'bonus_fleet'}
#: the part of each project directory
PROJECT_PART = {'hello': 'hello', 'web': 'web', 'cluster': 'cluster', 'provision': 'provision', 'sync': 'sync',
                'kiosk': 'kiosk', 'boxes/app': 'bonus_boxes', 'triggers': 'bonus_triggers', 'fleet': 'bonus_fleet'}
#: the part of each block of the files command
FILE_PART = {'cluster_vf': 'cluster', 'inventory': 'provision', 'triggers_vf': 'bonus_triggers',
             'triggers_log': 'bonus_triggers', 'fleet_vf': 'bonus_fleet', 'metadata_url': 'bonus_boxes'}
#: the state whose cheat answers fill the forms of a part
FORM_STATES = {'hello': 'solve_hello', 'web': 'solve_web', 'provision': 'solve_provision', 'kiosk': 'solve_kiosk'}
CHOICE_ELEMENTS = {'q_lifecycle', 'q_provisioning', 'q_ansible_local', 'q_macvlan'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('vagrant_lab_under_test', _LAB_PATH)
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


def _tr_literals():
    import check_sre_translations
    return check_sre_translations.get_tr_strings(ast.parse(_LAB_PATH.read_text()))


def _instructor_literals():
    """The literals of the tr() calls inside instructor() calls (also through _by_language)."""
    literals = []
    for node in ast.walk(ast.parse(_LAB_PATH.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'instructor':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'id', '') == 'tr' and sub.args \
                        and isinstance(sub.args[0], ast.Constant):
                    literals.append(sub.args[0].value)
    return literals


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


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


def _ups(ops, step):
    """The project directories of the `vagrant <args>` commands of *step*: [(project, args)]."""
    out = []
    for c in _cmds(ops, step, 'dev'):
        m = re.match(r'cd /root/vagrant/(\S+) && vagrant (\w+) --no-color --no-tty 2>&1$', c)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


# ---------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------


def part_of(machine, cmd):
    """The part a registered command belongs to (MACHINES / CONTAINERS / FILES: mixed)."""
    if machine == 'client':
        if 'http://dev:' in cmd:
            return 'web' if cmd.count('http://') == 1 else 'cluster'
        return 'kiosk'
    if '.vagrant/machines/*/docker/id' in cmd and cmd.startswith('for f in'):
        return 'MACHINES'
    if cmd.startswith('docker ps -aq'):
        return 'CONTAINERS'
    if cmd.startswith('docker network ls'):
        return 'SHARED'
    if cmd.startswith("echo '=== cluster_vf'"):
        return 'FILES'
    if 'eth0/address' in cmd:
        return 'SHARED'
    for project, part in (('hello', 'hello'), ('cluster', 'cluster'), ('provision', 'provision'), ('sync', 'sync'),
                          ('triggers', 'bonus_triggers')):
        if f"/root/vagrant/{project}/" in cmd:
            return part
    raise AssertionError(f"no part for {machine}: {cmd}")


def _project_part(project):
    rel = project[len('/root/vagrant/'):]
    return PROJECT_PART[rel]


def _blocks(text):
    blocks, name, lines = [], None, []
    for line in text.splitlines():
        if line.startswith('=== '):
            if name is not None:
                blocks.append((name, lines))
            name, lines = line[4:].strip(), []
        else:
            lines.append(line)
    if name is not None:
        blocks.append((name, lines))
    return blocks


class World:
    def __init__(self, done):
        self.done = set(done)
        self.outputs = {label: {(m, s, c): (o, code) for m, s, c, o, code in LIVE[label]}
                        for label in ('untouched', 'final')}
        final_listing = next(o for (m, s, c), (o, _code) in self.outputs['final'].items()
                             if part_of(m, c) == 'MACHINES')
        self.machines = parse_vagrant_machines(final_listing)
        self.kept_ids = {vm.id for (project, _n), vm in self.machines.items() if _project_part(project) in self.done}

    def output(self, machine, command, step):
        key = (machine, step, command)
        assert key in self.outputs['final'], f"command not in the capture: {machine} step {step}: {command}"
        part = part_of(machine, command)
        final, untouched = self.outputs['final'][key], self.outputs['untouched'][key]
        if part == 'SHARED':
            return final
        if part == 'MACHINES':
            lines = [line for line in final[0].splitlines()
                     if line.split('\t')[0] == 'M' and _project_part(line.split('\t')[1]) in self.done]
            return "".join(line + "\n" for line in lines), 0
        if part == 'CONTAINERS':
            items = json.loads(final[0].strip())
            return json.dumps([c for c in items if c['id'] in self.kept_ids], separators=(',', ':')) + "\n", 0
        if part == 'FILES':
            mixed = dict(_blocks(untouched[0]))
            for name, lines in _blocks(final[0]):
                if name == 'boxes':
                    keep = [line for line in lines if 'sre-VAGRANTSLASH-debian13' in line or 'bonus_boxes' in self.done]
                    mixed[name] = keep
                elif FILE_PART.get(name) in self.done:
                    mixed[name] = lines
            order = [name for name, _lines in _blocks(final[0])]
            return "".join(f"=== {name}\n" + "".join(line + "\n" for line in mixed.get(name, [])) for name in order), 0
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
    model = World(done)
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

    @pytest.mark.parametrize('seed', range(20))
    def test_values(self, lab, seed):
        import random
        random.seed(seed)
        d = lab.Data.generate()
        d.compute_post_generate()
        assert d.company in lab.COMPANIES and re.fullmatch(r'\d+\.\d+\.\d+', d.box_version)
        assert 8100 <= d.web_port <= 8499 and 8500 <= d.cluster_port <= 8899 and 5001 <= d.app_port <= 5999
        lan = d.nets.lan
        assert lan.prefixlen == 24 and not any(lan.overlaps(IPv4Network(n)) for n in (
            "172.16.0.0/12", "192.168.0.0/16", "10.250.0.0/15", "10.0.0.0/16"))
        assert str(d.ips.dev.ip).endswith('.10') and str(d.ips.client.ip).endswith('.100')
        assert str(d.ips.gateway.ip).endswith('.1')
        rng = d.nets.kiosk_range
        assert rng.prefixlen == 29 and rng.subnet_of(lan) and d.ips.kiosk.ip in rng
        assert d.ips.kiosk.ip not in (rng.network_address, rng.broadcast_address)
        assert not any(ip in rng for ip in (d.ips.dev.ip, d.ips.client.ip, d.ips.gateway.ip))
        assert d.nets.cluster != d.nets.fleet and d.nets.cluster.subnet_of(IPv4Network("192.168.0.0/16"))
        names = [m['name'] for m in d.fleet]
        assert len(set(names)) == 3 and all(n in lab.FLEET_POOL for n in names)
        assert len({m['ip'] for m in d.fleet}) == 3 and all(m['ip'].startswith(str(d.nets.fleet)[:-5]) for m in d.fleet)
        assert d.box_image == f"sre/debian13:{d.box_version}" and d.catalog_box == f"{d.company}/base"
        assert d.web_token.startswith(d.company.upper() + '-') and d.kiosk_token.startswith('KIOSK-')

    def test_topology(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'dev', 'client'}
        dev = lab.NetScheme._machine_specs['dev']
        assert dev['privileged'] and dev['entrypoint'] == '/sbin/init' and dev['image'].split('/')[-1].startswith(
            'devops13:')
        assert lab.NetScheme._network_specs['lan']['mode'] == 'switch'
        assert ns.get_weight() == 120 + params.default_machine_weight


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        files = _files(ops, 1, 'dev')
        assert json.loads(files['/opt/boxes/build/metadata.json']) == {"provider": "docker"}
        assert f'd.image = "sre/debian13:{fresh.box_version}"' in files['/opt/boxes/build/Vagrantfile']
        catalog = json.loads(files['/opt/boxes/debian13.json.in'])
        assert catalog['name'] == 'sre/debian13' and catalog['versions'][0]['version'] == fresh.box_version
        assert fresh.web_token in files['/root/vagrant/web/site/index.html']
        assert 'hosts: databases' in files['/root/vagrant/provision/site.yml']
        assert all(m['name'] in files['/root/vagrant/fleet/machines.yml'] for m in fresh.fleet)
        assert files['/etc/hosts'] == f"127.0.0.1\tlocalhost\n{fresh.ips.dev.ip}\tdev\n{fresh.ips.client.ip}\tclient\n"
        cmds = _cmds(ops, 2, 'dev')
        assert cmds[1].startswith("timeout 30 sh -c") and cmds[2].startswith("systemctl start docker")
        assert f"sre/debian13:{fresh.box_version}" in cmds[3] and 'docker import' in cmds[3]
        assert cmds[-1] == "vagrant box add /opt/boxes/debian13.json --no-color --no-tty"
        assert not any('ip_forward' in c for c in _cmds(ops, 1, 'dev'))

    def test_playbook_and_machines_are_yaml(self, lab, fresh):
        yaml = pytest.importorskip('yaml')
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        play = yaml.safe_load(ns.playbook())
        assert play[0]['hosts'] == 'databases' and play[0]['become'] is True
        assert [t['name'] for t in play[0]['tasks']][0] == 'Les variables sont fournies'
        assert yaml.safe_load(ns.machines_yml(fresh)) == fresh.fleet

    def test_solve_states(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        expected = {
            'solve_hello': ({'hello/Vagrantfile'}, [('hello', 'up')], []),
            'solve_web': ({'web/Vagrantfile'}, [('web', 'up')], [('web', 'reload')]),
            'solve_cluster': ({'cluster/Vagrantfile'}, [('cluster', 'up')], []),
            'solve_provision': ({'provision/Vagrantfile'}, [('provision', 'up')], []),
            'solve_sync': ({'sync/Vagrantfile'}, [('sync', 'up')], []),
            'solve_kiosk': ({'kiosk/Vagrantfile'}, [('kiosk', 'up')], []),
            'solve_boxes': ({'boxes/build-1.0.0/metadata.json', 'boxes/build-1.0.0/Vagrantfile',
                             'boxes/build-1.1.0/metadata.json', 'boxes/build-1.1.0/Vagrantfile', 'boxes/app/Vagrantfile'},
                            [('boxes/app', 'up')], []),
            'solve_triggers': ({'triggers/Vagrantfile'}, [('triggers', 'up')], []),
            'solve_fleet': ({'fleet/Vagrantfile'}, [('fleet', 'up')], []),
        }
        for state, (paths, ups2, ups3) in expected.items():
            ops = _state_ops(ns, state)
            files = {p[len('/root/vagrant/'):] for p in _files(ops, 1, 'dev') if p.startswith('/root/vagrant/')}
            assert files == paths, state
            assert _ups(ops, 2) == ups2 and _ups(ops, 3) == ups3, state
        boxes = _state_ops(ns, 'solve_boxes')
        adds = [c for c in _cmds(boxes, 2, 'dev') if 'vagrant box add' in c]
        assert adds == [f"cd /root/vagrant/boxes && vagrant box add catalog.json --box-version {v} --force "
                        "--no-color --no-tty" for v in lab.BOX_VERSIONS]
        final = _state_ops(ns, 'final')
        assert [p for p, _a in _ups(final, 2)] == ['hello', 'web', 'cluster', 'provision', 'sync', 'kiosk', 'boxes/app',
                                                   'triggers', 'fleet']
        assert _ups(final, 3) == [('web', 'reload')]

    def test_reference_vagrantfiles(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        d = fresh
        assert f'config.vm.hostname = "{d.hello_hostname}"' in ns.vf_hello()
        web = ns.vf_web()
        assert f'guest: 80, host: {d.web_port}' in web and 'run: "always"' in web and '"file"' in web
        cluster = ns.vf_cluster()
        assert '(1..2).each do |i|' in cluster and f'host: {d.cluster_port}' in cluster
        assert f'server {d.cluster_ip("app1")};' in cluster and 'app1' not in cluster.replace('app#{i}', '')
        prov = ns.vf_provision()
        assert '"databases" => ["db"]' in prov and f'app_port: {d.app_port}' in prov
        sync = ns.vf_sync()
        assert '"/vagrant", disabled: true' in sync and f'd.name = "{d.sync_name}"' in sync
        kiosk = ns.vf_kiosk()
        assert f'docker_network__ip_range: "{d.nets.kiosk_range}"' in kiosk and 'bridge: "eth0"' in kiosk
        assert f'ip: "{d.ips.kiosk.ip}"' in kiosk and d.kiosk_token in kiosk
        assert 'config.vm.box_version = "1.0.0"' in ns.vf_boxes_app()
        trig = ns.vf_triggers()
        assert 'config.trigger.after :up do |t|' in trig and 'machine.id' in trig and 'run_remote' in trig
        fleet = ns.vf_fleet()
        assert 'YAML.load_file' in fleet and not any(m['name'] in fleet or m['ip'] in fleet for m in d.fleet)
        catalog = json.loads(ns.catalog_template())
        assert [v['version'] for v in catalog['versions']] == ['1.0.0', '1.1.0']
        assert catalog['versions'][0]['providers'][0]['url'] == 'file:///root/vagrant/boxes/base-1.0.0.box'
        assert 'BOX_RELEASE" => "1.1.0"' in ns.box_build_files('1.1.0')[1]


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_capture_is_complete(self, lab, data, tmp_pub_dir):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        registered = {(m, s, c) for (m, s), cmds in grade.get_tests().items() for (c, _t) in cmds}
        captured = {(m, s, c) for m, s, c, _o, _code in LIVE['final']}
        assert registered == captured
        assert captured == {(m, s, c) for m, s, c, _o, _code in LIVE['untouched']}

    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, done=(), answers=False)
        assert _totals(grade) == (0, 0)

    def test_everything(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data)
        assert {t: g for t, g in _grades(grade).items() if g[0] != g[1]} == {}
        assert _totals(grade) == (87, 12)
        assert _parts(grade) == POINTS
        assert {str(e.title) for e in grade.get_grade_list() if e.bonus} == {
            'boxes_catalog', 'boxes_pinned', 'boxes_env', 'triggers_log', 'triggers_remote', 'triggers_declared',
            'fleet_machines', 'fleet_yaml'}

    @pytest.mark.parametrize('part', PARTS)
    def test_each_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, done=(part,))
        parts = _parts(grade)
        assert parts[part] == POINTS[part]
        assert sum(parts.values()) == POINTS[part]

    @pytest.mark.parametrize('part', PARTS)
    def test_all_but_one(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, done=[p for p in PARTS if p != part])
        parts = _parts(grade)
        assert parts[part] == 0
        assert sum(parts.values()) == sum(POINTS.values()) - POINTS[part]

    def test_choices_are_for_the_instructor(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data)
        scopes = {str(e.title): e.scope for e in grade.get_grade_list()}
        assert {t for t, s in scopes.items() if s == params.EXO_EVAL_SCOPE} == CHOICE_ELEMENTS

    def test_forms_without_answers(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, answers=False)
        lost = {t for t, (g, m) in _grades(grade).items() if g != m}
        assert lost == {'q_box_version', 'q_lifecycle', 'q_provisioning', 'q_inventory', 'q_ansible_local', 'q_macvlan'}

    def test_restart_needed(self, lab, data, tmp_pub_dir, monkeypatch):
        """A web container never restarted (the run "always" provisioner untested) loses that element."""
        original = World.output

        def no_restart(self, machine, command, step):
            out, code = original(self, machine, command, step)
            if command.startswith('docker ps -aq'):
                items = json.loads(out)
                for c in items:
                    if c['name'].startswith('web_web_'):
                        c['started'] = c['created']
                out = json.dumps(items)
            return out, code

        monkeypatch.setattr(World, 'output', no_restart)
        grade, _ = _simulate(lab, data)
        assert {t for t, (g, m) in _grades(grade).items() if g != m} == {'web_restart'}

    def test_hand_made_container_scores_nothing(self, lab, data, tmp_pub_dir, monkeypatch):
        """The containers are there but Vagrant recorded none of them (made with docker run): only the
        boxes installed from the catalog (no machine needed) still count."""
        original = World.output

        def no_vagrant(self, machine, command, step):
            if part_of(machine, command) == 'MACHINES':
                return '', 0
            return original(self, machine, command, step)

        monkeypatch.setattr(World, 'output', no_vagrant)
        grade, _ = _simulate(lab, data, answers=False)
        assert _totals(grade) == (0, 2)
        assert {t for t, (g, m) in _grades(grade).items() if g} == {'boxes_catalog'}

    def test_fleet_written_by_hand(self, lab, data, tmp_pub_dir, monkeypatch):
        """Machines named in the Vagrantfile instead of read from the YAML file: fleet_yaml lost."""
        original = World.output

        def literal(self, machine, command, step):
            out, code = original(self, machine, command, step)
            if part_of(machine, command) == 'FILES':
                out = out.replace("=== fleet_vf\n", f"=== fleet_vf\n# {data.fleet[0]['name']} in a comment\n"
                                                    f"config.vm.define \"{data.fleet[0]['name']}\"\n")
            return out, code

        monkeypatch.setattr(World, 'output', literal)
        grade, _ = _simulate(lab, data)
        assert {t for t, (g, m) in _grades(grade).items() if g != m} == {'fleet_yaml'}


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


class TestTexts:
    def test_course(self, lab, fresh):
        ns = lab.NetScheme(data=fresh, running_lab_name=_running_name())
        from SRE.informations import resolve_informations
        resolved, _numbering = resolve_informations(ns.informations)      # (text, numbering)
        text = _text(resolved)
        assert '\n## ' in text or text.startswith('## ')
        for word in ('Vagrantfile', 'box', 'forwarded_port', 'macvlan', 'run: "always"', 'ansible_local',
                     'YAML.load_file', 'trigger', 'Aide-mémoire', 'BSL'):
            assert word in text
        html = markdown_to_html(text)
        assert '```' not in html and '@@' not in html
        # every table renders as a table (no `|` cell split by a pipe in inline code)
        assert html.count('<table>') == len(re.findall(r'^\|[-|: ]+\|$', text, re.M)) == 5
        for table in re.findall(r'<table>.*?</table>', html, re.S):
            rows = re.findall(r'<tr>(.*?)</tr>', table, re.S)
            widths = {len(re.findall(r'<t[hd]', r)) for r in rows}
            assert len(widths) == 1, table[:300]

    def test_questions_render(self, lab, data, tmp_pub_dir):
        for mode in (False, True):
            grade, _ = _simulate(lab, data, instructor_mode=mode)
            for q in grade.get_questions_ordered():
                for t in (q.title, q.description):
                    s = _text(t)
                    assert "{'" not in s and not re.search(r'(?<!#)\{[a-z_]+\}', s), s[:200]   # Ruby: #{i}
                    html = markdown_to_html(s, show_instructor=mode)
                    assert '```' not in html
                    for table in re.findall(r'<table>.*?</table>', html, re.S):
                        widths = {len(re.findall(r'<t[hd]', r)) for r in re.findall(r'<tr>(.*?)</tr>', table, re.S)}
                        assert len(widths) == 1
            texts = [_text(q.description) for q in grade.get_questions_ordered()]
            assert sum(has_instructor(t) for t in texts) == (15 if mode else 0)

    def test_values_in_texts(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, instructor_mode=True)
        text = "\n".join(_text(q.description) for q in grade.get_questions_ordered())
        for value in (data.hello_hostname, str(data.web_port), str(data.cluster_port), data.app_user, str(data.app_port),
                      data.app_env, data.sync_name, data.sync_mode, data.kiosk_token, str(data.ips.kiosk.ip),
                      str(data.nets.kiosk_range), str(data.ips.gateway.ip), data.catalog_box, data.box_version,
                      data.cluster_ip('app1'), data.cluster_ip('lb'), *(m['ip'] for m in data.fleet)):
            assert value in text

    def test_form_fields(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data)
        names = [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', None) or []]
        assert names == ['box_version', 'stop', 'reread', 'delete', 'everywhere', 'after_restart', 'rerun', 'inventory',
                         'local', 'why']

    def test_translations(self, lab, data, tmp_pub_dir):
        """Every tr() text has its English in _TRANSLATIONS['en'] (the markup kept: checked for every lab of
        the directory by test_draft_misc_translations.py); the instructor texts read in both languages and
        the dropdowns of the English forms show English labels over the values of the French ones."""
        from SRE import form_spec
        english = lab._TRANSLATIONS['en']
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        assert set(english) == _tr_literals() and set(_instructor_literals()) <= set(english)
        assert all(english.values()) and [k for k, v in english.items() if v == k] == ['Architecture']
        assert _text(lab.title, 'en') == "Vagrant: reproducible environments"
        assert _text(lab.NetScheme.solve_fleet._sre_state_description, 'en') == \
            "Bonus 3: solution (YAML-driven Vagrantfile)"
        grade, _ = _simulate(lab, data, instructor_mode=True)
        labels = {}
        for q in grade.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert fr != en and "{'" not in en and not re.search(r'(?<!#)\{[a-z_]+\}', en), _text(q.title)
            assert form_spec.form_fields(fr) == form_spec.form_fields(en), _text(q.title)
            assert has_instructor(en) == has_instructor(fr)
            assert not has_instructor(en) or '**Solution.**' in en or '**For the instructor.**' in en
            for lang, text in (('fr', fr), ('en', en)):
                for chunk in form_spec.field_chunks(form_spec.parse_form_description(text)):
                    if chunk.kind == 'select':
                        labels[chunk.name, lang] = chunk.labels
        for name in ('after_restart', 'local', 'why'):
            assert labels[name, 'en'] != labels[name, 'fr']
            assert not any(re.search(r'[éèêàùçô]', label) for label in labels[name, 'en']), labels[name, 'en']
        assert labels['why', 'en'][0] == "macvlan isolates the parent interface from its sub-interfaces"
        # the French values of a solution built in code have their English (the reference files stay French)
        text = "\n".join(_text(q.description, 'en') for q in grade.get_questions_ordered())
        assert 'machine started' in text and 'machine démarrée' not in text and '<sha256 of base-' in text
        assert 't.info = "machine démarrée"' in lab.NetScheme(data=data, running_lab_name=_running_name()).vf_triggers()

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(') == len(_instructor_literals()) == 15
        assert result.warnings == []
        assert b'**Solution' not in result.data and b"Pour l'enseignant" not in result.data
        assert b'For the instructor' not in result.data
        stripped = tmp_path / 'vagrant_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('vagrant_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # the English of the instructor texts goes with them, every other entry stays
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(set(_instructor_literals()))
        grade, _ = _simulate(module, data, instructor_mode=True)
        assert _totals(grade) == (87, 12)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, fresh, tmp_pub_dir):
        french = re.compile(r'(?:^|[_.:-])(routeur|reseau|partie|adresse|serveur|compte|cle|groupe|machine_|'
                            r'nom|depot|boite)(?:$|[_.:-])', re.I)
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
        assert 'initial' in names and 'final' in names and 'solve_kiosk' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
