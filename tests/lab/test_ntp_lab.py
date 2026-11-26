"""Offline tests of the NTP / chrony lab (lab/sre/_DRAFT_misc/ntp.py).

No Docker: a model of the company (``World``) holds what has been done, as a set of features
(``border``, ``ts1``, ``cam1``...), and renders what the grader reads in the shapes captured live on s17
(tests/mock_data/ntp/): the ``chronyc -c -n`` snapshot of each machine, the JSON of ``ntp_probe.py
check``.  The behaviours follow what was seen live: a falseticker marked ``x``, an unsynchronised server
``?`` with Reach 0, chronyd not running (``506 Cannot talk to daemon``) when ``-x`` is missing or the
configuration is invalid, a client of an unsynchronised or unreachable server not synchronised.  Covers
the data, the topology, the states, the two-pass grading contract (nothing done: 0; everything: 81 + 6
bonus points; **each part alone gives exactly its points and everything but one part the rest**) and
the texts.
"""
import datetime
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import ntp  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'ntp.py'

PARTS = {
    'part1': set(),
    'part2': {'border'},
    'part3': {'ts1', 'pcs'},
    'part4': {'ts2', 'cam1'},
    'part5': {'ts3', 'web1'},
    'part6': {'legacy'},
    'bonus': {'border_public'},
}
POINTS = {'part1': 9, 'part2': 18, 'part3': 18, 'part4': 12, 'part5': 12, 'part6': 12, 'bonus': 6}
SOLVE_STATE = {part: f'solve_{part}' for part in PARTS}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {'answer_delay': 'part1', 'answer_offset': 'part1', 'answer_stratum': 'part1',
                 'answer_port': 'part1', 'answer_epoch': 'part1', 'answer_precision': 'part1',
                 'answer_false_server': 'part2', 'answer_false_offset': 'part2', 'answer_unsync_server': 'part2',
                 'answer_nts_port': 'part5', 'answer_kod': 'bonus'}
FORM_POINTS = {'part1': 9, 'part2': 6, 'part5': 2, 'bonus': 1}
BONUS_ELEMENTS = ['border_serves_wan', 'border_ratelimit', 'answer_kod']
TRACKING_UNSYNC = ("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,"
                   "1.000000000,1.000000000,0.0,Not synchronised")
NOT_RUNNING = "506 Cannot talk to daemon"


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ntp_lab_under_test', _LAB_PATH)
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


def _mentions(text, value):
    return re.search(r'(?<![0-9A-Za-z.])' + re.escape(value) + r'(?![0-9A-Za-z])', text) is not None


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


def _cmds(ops, machine, step=None):
    return [str(op) for (s, m), op_list in ops.items() for op in op_list
            if m == machine and (step is None or s == step) and isinstance(op, str)]


def _files(ops, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for (s, m), op_list in ops.items() for op in op_list if m == machine and not isinstance(op, str)}


# ---------------------------------------------------------------------------
# the model
# ---------------------------------------------------------------------------


def _tracking(address, stratum):
    return (f"{ntp.refid_of(address)},{address},{stratum},1795447999.797422689,0.000020656,-0.000020743,"
            "0.000020743,0.015,4.010,1.309,0.001280320,0.000445269,0.0,Normal")


def _source(state, address, stratum, reach='377', offset=0.000017):
    return f"^,{state},{address},{stratum},6,{reach},1,{offset:.9f},{offset:.9f},0.001040022"


def _auth(address, mode='-', keyid=0, cookies=0):
    if mode == 'SK':
        return f"{address},SK,{keyid},3,256,4294967295,0,0,0,0"
    if mode == 'NTS':
        return f"{address},NTS,1,30,128,40,0,0,{cookies},64"
    return f"{address},-,0,0,0,4294967295,0,0,0,0"


def _snapshot(running=True, tracking=None, sources=(), auth=(), config=None):
    sep = "==SRE-NTP=="
    blocks = [f"{sep}pid", "219 218" if running else ""]
    blocks += [f"{sep}tracking", (tracking or TRACKING_UNSYNC) if running else NOT_RUNNING]
    blocks += [f"{sep}sources"] + (list(sources) if running else [NOT_RUNNING])
    blocks += [f"{sep}authdata"] + (list(auth) if running else [NOT_RUNNING])
    if config is not None:
        blocks += [f"{sep}config"] + list(config)
    return "\n".join(blocks) + "\n"


BASE_CONFIG = [line for line in ntp.base_chrony_conf().splitlines() if not line.startswith('confdir')]


class World:
    """What the students did: *features* (see PARTS), plus variants for the negative tests:
    ``border_three`` (the falseticker left out), ``ts1_allow_all``, ``ts1_no_local``, ``cam1_nokey``,
    ``web1_nonts``, ``legacy_daemon`` / ``legacy_network`` (one or two of the three faults fixed),
    ``bonus_nolimit`` (border serves wan without a rate limit)."""

    def __init__(self, ns, features):
        self.ns, self.d, self.f = ns, ns.data, set(features)
        self.ip = {name: str(getattr(self.d.ips, name).ip) for name in vars(self.d.ips)}

    def snapshot(self, m):
        d, f, ip = self.d, self.f, self.ip
        if m == 'border':
            if 'border' not in f:
                return _snapshot()
            sources = []
            for name, role in zip(('ntp1', 'ntp2', 'ntp3', 'ntp4'), d.roles):
                if role == 'gps':
                    sources.append(_source('*', ip[name], 1))
                elif role == 'secondary':
                    sources.append(_source('-', ip[name], 2))
                elif role == 'false' and 'border_three' not in f:
                    sources.append(_source('x', ip[name], 2, offset=-d.false_offset))
                elif role == 'unsync':
                    sources.append(_source('?', ip[name], 0, reach='0', offset=0))
            return _snapshot(tracking=_tracking(ip[d.public_by_role('gps')], 2), sources=sources)
        if m == 'ts1':
            if 'ts1' not in f:
                return _snapshot(config=BASE_CONFIG)
            config = ["server gps.corp.lan iburst", f"allow {d.nets.srv}",
                      f"allow {'0.0.0.0/0' if 'ts1_allow_all' in f else d.nets.lan}"]
            if 'ts1_no_local' not in f:
                config.append("local stratum 10 orphan")
            return _snapshot(tracking=_tracking(ip['gps'], 2), sources=[_source('*', ip['gps'], 1)],
                             auth=[_auth(ip['gps'])], config=config + BASE_CONFIG)
        if m in ('pc1', 'pc2'):
            if 'pcs' not in f:
                return _snapshot()
            if 'ts1' not in f:   # ts1 does not answer
                return _snapshot(sources=[_source('?', ip['ts1'], 0, reach='0', offset=0)])
            return _snapshot(tracking=_tracking(ip['ts1'], 3), sources=[_source('*', ip['ts1'], 2)])
        if m == 'cam1':
            if 'cam1' not in f or 'ts2' not in f:
                return _snapshot()
            mode = '-' if 'cam1_nokey' in f else 'SK'
            return _snapshot(tracking=_tracking(ip['ts2'], 3), sources=[_source('*', ip['ts2'], 2)],
                             auth=[_auth(ip['ts2'], mode, d.key_id)])
        if m == 'web1':
            if 'web1' not in f or 'ts3' not in f:
                return _snapshot()
            mode = '-' if 'web1_nonts' in f else 'NTS'
            return _snapshot(tracking=_tracking(ip['ts3'], 3), sources=[_source('*', ip['ts3'], 2)],
                             auth=[_auth(ip['ts3'], mode, cookies=8)])
        if m == 'legacy':
            if 'legacy' in f:
                return _snapshot(tracking=_tracking(ip['gps'], 2), sources=[_source('*', ip['gps'], 1)])
            if 'legacy_daemon' not in f:
                return _snapshot(running=False)
            reach = '377' if 'legacy_network' in f else '0'
            return _snapshot(sources=[_source('?', ip['gps'], 1 if reach != '0' else 0, reach=reach)])
        raise AssertionError(f"no snapshot for {m}")

    def probe(self, spec):
        f = self.f
        synced_answer = {'answered': True, 'leap': 0, 'mode': 4, 'stratum': 2, 'refid': self.ip['gps'],
                         'offset': 0.00002, 'delay': 0.0005}
        result = {}
        for item in spec:
            ident = item['id']
            if ident in ('ts1_lan', 'ts1_srv'):
                result[ident] = synced_answer if 'ts1' in f else {'answered': False}
            elif ident == 'ts1_dmz':
                result[ident] = synced_answer if {'ts1', 'ts1_allow_all'} <= f else {'answered': False}
            elif ident == 'ts2_key':
                result[ident] = {'synced': 'ts2' in f, 'offset': 0.0001 if 'ts2' in f else None, 'output': ''}
            elif ident == 'ts2_badkey':
                result[ident] = {'synced': False, 'offset': None, 'output': 'Timeout reached'}
            elif ident == 'ts3_nts':
                result[ident] = {'synced': 'ts3' in f, 'offset': 0.0001 if 'ts3' in f else None, 'output': ''}
            elif ident == 'border_wan':
                result[ident] = dict(synced_answer, leap=0 if 'border' in f else 3) if 'border_public' in f \
                    else {'answered': False}
            elif ident == 'border_burst':
                answered = 0 if 'border_public' not in f else (30 if 'bonus_nolimit' in f else 13)
                result[ident] = {'sent': item['count'], 'answered': answered}
            else:
                raise AssertionError(f"unexpected probe {ident}")
        return result

    def output(self, machine, command, step):
        assert step == 1
        if command in (ntp.snapshot_cmd(True), ntp.snapshot_cmd(False)):
            assert (command == ntp.snapshot_cmd(True)) == (machine == 'ts1')
            return self.snapshot(machine), 0
        if machine == 'probe' and command.startswith(f"python3 {ntp.NTP_PROBE_PATH} check "):
            spec = json.loads(shlex.split(command)[3])
            return json.dumps(self.probe(spec)) + "\n", 0
        raise AssertionError(f"unexpected command on {machine}: {command}")


def _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES, answers='final', instructor_mode=False, extra=None):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  *answers*: the state whose
    cheat answers fill the forms (None: no answer); *extra*: answers that replace them."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    model = World(ns, features)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            grade._answers = dict(grade.get_cheat_answers(answers) or {}) if answers else {}
            for q_hash, fields in (extra or {}).items():   # a form's answers are stored as JSON
                grade._answers[q_hash] = json.dumps(dict(json.loads(grade._answers.get(q_hash, '{}')), **fields))
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


def _lost(grade):
    return {title for title, (got, best) in _grades(grade).items() if got != best}


def _parts(grade):
    result = {str(p.title): 0 for p in grade.get_grade_parts()}
    for e in grade.get_grade_list():
        result[str(e.grade_part)] += e.grade
    return result


def _form_hash(grade, field):
    """The hash of the question holding the form field *field*."""
    for q in grade.get_questions_ordered():
        if field in [f['name'] for f in getattr(q, 'fields', None) or []]:
            return q.question_hash
    raise KeyError(field)


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        again = lab.Data.from_dict(data.to_dict())
        assert again.to_dict() == data.to_dict()

    def test_values(self, lab):
        for _ in range(30):
            d = lab.Data.generate()
            assert sorted(d.roles) == sorted(lab.ROLES)
            assert 40 <= abs(d.false_offset) <= 400
            assert d.faults[0] in lab.DAEMON_FAULTS and d.faults[1] in lab.NETWORK_FAULTS
            assert d.faults[2] in lab.SELECTION_FAULTS
            assert re.fullmatch(r'[0-9A-F]{64}', d.key_secret) and d.key_secret != d.wrong_secret
            assert 10 <= d.key_id <= 99 and d.gps_precision in (-24, -23, -22, -21, -19, -18)
            # the exchange: integer milliseconds, the formulas of the course
            assert d.exchange_delay == (d.t4 - d.t1) - (d.t3 - d.t2) > 0
            assert 2 * d.exchange_offset == (d.t2 - d.t1) + (d.t3 - d.t4)
            assert d.exchange_offset != 0 and d.t1 < d.t4
            assert re.fullmatch(r'\d\d:\d\d:\d\d\.\d{3}', lab.hms(d.t2))
            assert 'BEGIN CERTIFICATE' in d.ts3_cert and 'PRIVATE KEY' in d.ts3_key

    def test_addresses(self, lab, data):
        assert data.nets.wan.subnet_of(__import__('ipaddress').IPv4Network('198.18.0.0/15'))
        nets = [data.nets.wan, data.nets.srv, data.nets.lan, data.nets.iot, data.nets.dmz]
        assert len({str(n) for n in nets}) == 5
        for name, net in (('ntp1', 'wan'), ('gps', 'srv'), ('ts1', 'srv'), ('pc1', 'lan'), ('ts2', 'iot'),
                          ('ts3', 'dmz'), ('probe_wan2', 'wan')):
            assert getattr(data.ips, name).ip in getattr(data.nets, net), name
        assert lab.hms(3723004) == '01:02:03.004'


class TestTopology:
    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert set(specs) == {'edge', 'internet', 'gps', 'border', 'ts1', 'ts2', 'ts3', 'pc1', 'pc2', 'legacy',
                              'cam1', 'web1', 'probe'}
        for name, spec in specs.items():
            # never privileged: a privileged container may change the clock of the host
            assert not spec.get('privileged') and 'entrypoint' not in spec, name
            assert spec['image'] == lab.sre_docker_image('netdev13'), name
        assert specs['probe']['hidden'] and not specs['probe']['allow_connection']
        assert specs['internet']['allow_connection'] is False and specs['gps']['allow_connection'] is False
        assert lab.export_kathara_project is False

    def test_every_network_has_edge(self, lab):
        topo = lab.NetScheme._topology
        assert set(topo) == {'wan', 'srv', 'lan', 'iot', 'dmz'}
        assert [topo[n]['edge'] for n in ('wan', 'srv', 'lan', 'iot', 'dmz')] == [0, 1, 2, 3, 4]
        assert sorted(topo[n]['probe'] for n in topo) == [0, 1, 2, 3, 4]


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        # the fake servers: four personalities on internet (their roles), one on gps
        internet = " ".join(_cmds(ops, 'internet'))
        config = json.loads(shlex.split(internet.split(' serve ', 1)[1].split(' >/dev/null')[0])[0])
        by_address = {p['address']: p for p in config}
        for name, role in zip(('ntp1', 'ntp2', 'ntp3', 'ntp4'), data.roles):
            p = by_address[str(getattr(data.ips, name).ip)]
            assert (p['leap'] == 3) == (role == 'unsync') and (p['offset'] != 0) == (role == 'false')
            assert p['stratum'] == {'gps': 1, 'secondary': 2, 'false': 2, 'unsync': 16}[role]
        assert by_address[str(data.ips.ntp1.ip)] is not None
        gps = " ".join(_cmds(ops, 'gps'))
        assert f'"precision": {data.gps_precision}' in gps and '"refid": "GPS"' in gps
        # chrony: Debian's file without its pool, -x, a drift seed, started
        for m in lab.CHRONY_MACHINES:
            files = _files(ops, m)
            assert 'pool ' not in files[ntp.CHRONY_CONF] and ' -x ' in files[ntp.CHRONY_DEFAULTS] or m == 'legacy'
            assert files[ntp.DRIFT_FILE] == ntp.DRIFT_SEED
        for m in ('border', 'ts1', 'ts2', 'ts3', 'pc1', 'pc2', 'cam1', 'web1', 'legacy'):
            assert any('service chrony start' in c for c in _cmds(ops, m)), m
        # NTS material, the probe's keys and tables
        ts3 = _files(ops, 'ts3')
        assert ts3[lab.TS3_KEY] == data.ts3_key and ts3[lab.TS3_CERT] == data.ts3_cert
        assert [op.permissions for (s, m), l in ops.items() for op in l
                if m == 'ts3' and not isinstance(op, str) and op.filename == lab.TS3_KEY] == [0o600]
        assert _files(ops, 'web1')[lab.NTS_CA] == data.ca_cert
        probe = _files(ops, 'probe')
        assert data.key_secret in probe[f"{lab.PROBE_DIR}/good.keys"]
        assert data.wrong_secret in probe[f"{lab.PROBE_DIR}/bad.keys"]
        rules = [c for c in _cmds(ops, 'probe') if c.startswith('ip rule add')]
        assert len(rules) == 4 and any(str(data.ips.probe_wan2.ip) in r for r in rules)
        assert ntp.NTP_PROBE_PATH in probe

    def test_legacy_faults(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for faults in (['nox', 'port', 'noselect'], ['syntax', 'nft', 'minsources'], ['nox', 'nft', 'maxdistance']):
            ns.data.faults = faults
            files = ns.legacy_files()
            assert (' -x ' in files[ntp.CHRONY_DEFAULTS]) == ('nox' not in faults)
            sources = files[lab.LEGACY_SOURCES]
            assert ('port 1123' in sources) == ('port' in faults) and ('noselect' in sources) == ('noselect' in faults)
            conf = files[lab.LEGACY_CONF]
            assert ('serveur ' in conf) == ('syntax' in faults) and ('minsources 2' in conf) == ('minsources' in faults)
            assert ('maxdistance' in conf) == ('maxdistance' in faults)
            ops = _state_ops(ns, 'initial')
            assert any('nft -f' in c for c in _cmds(ops, 'legacy')) == ('nft' in faults)
        ns.data.faults = data.faults

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'solve_part3')
        assert _files(ops, 'ts1')[lab.LAB_CONF] == ns.sol_ts1()
        assert 'local stratum 10 orphan' in ns.sol_ts1() and f"allow {data.nets.lan}" in ns.sol_ts1()
        assert {s for (s, m) in ops if m in ('pc1', 'pc2')} == {3, 4}   # after ts1 is synchronised
        ops = _state_ops(ns, 'solve_part4')
        assert data.key_secret in _files(ops, 'ts2')[ntp.CHRONY_KEYS] == _files(ops, 'cam1')[ntp.CHRONY_KEYS]
        assert f"key {data.key_id}" in _files(ops, 'cam1')[lab.LAB_CONF]
        ops = _state_ops(ns, 'solve_part5')
        assert any(f"chgrp _chrony {lab.TS3_KEY}" in c for c in _cmds(ops, 'ts3'))
        assert ' nts' in _files(ops, 'web1')[lab.LAB_CONF]
        ops = _state_ops(ns, 'solve_part6')
        assert ' -x ' in _files(ops, 'legacy')[ntp.CHRONY_DEFAULTS]
        assert any('nft delete table inet filter' in c for c in _cmds(ops, 'legacy'))
        ops = _state_ops(ns, 'solve_bonus')
        assert f"ratelimit interval {lab.RATE_INTERVAL} burst {lab.RATE_BURST}" in _files(ops, 'border')[lab.PUBLIC_CONF]
        assert _state_ops(ns, 'solve_part1') == {}

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())

        def flat(ops):
            return sorted((s, m, str(op) if isinstance(op, str) else op.filename) for (s, m), l in ops.items() for op in l)

        union = []
        for part in PARTS:
            union += flat(_state_ops(ns, SOLVE_STATE[part]))
        assert flat(_state_ops(ns, 'final')) == sorted(union)


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 81
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len({str(e.title) for e in elements}) == len(elements) == 31

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (81, 6)
        assert _parts(grade) == POINTS

    @pytest.mark.parametrize('part', list(PARTS))
    def test_a_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=PARTS[part], answers=SOLVE_STATE[part])
        assert _parts(grade) == {key: (POINTS[key] if key == part else 0) for key in POINTS}

    @pytest.mark.parametrize('part', list(PARTS))
    def test_everything_but_a_part(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - PARTS[part], answers='final')
        # the answers of the forms stay: the part keeps the points of its forms
        assert _parts(grade) == {key: (FORM_POINTS.get(part, 0) if key == part else POINTS[key]) for key in POINTS}

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(10):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (81, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert {e.scope for e in grade.get_grade_list()} == {params.BOTH_EVAL_SCOPE}
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == BONUS_ELEMENTS

    def test_answers_only_and_wrong_answers(self, lab, data, tmp_pub_dir):
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _lost(answers_only) == set(_grades(answers_only)) - set(FORM_ELEMENTS)
        assert _totals(answers_only) == (17, 1)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (64, 5)

    @pytest.mark.parametrize('variant, removed, lost', [
        ('border_three', set(), {'border_sources', 'border_falseticker'}),
        ('ts1_allow_all', set(), {'ts1_refuses_dmz'}),
        ('ts1_no_local', set(), {'ts1_local'}),
        (None, {'ts1'}, {'ts1_synced', 'ts1_serves_lan', 'ts1_serves_srv', 'ts1_refuses_dmz', 'ts1_local',
                         'pc1_synced', 'pc2_synced'}),
        (None, {'pcs'}, {'pc1_synced', 'pc2_synced'}),
        (None, {'ts2'}, {'ts2_key', 'ts2_wrong_key', 'cam1_key'}),
        (None, {'cam1'}, {'cam1_key'}),
        ('cam1_nokey', set(), {'cam1_key'}),
        (None, {'ts3'}, {'ts3_nts', 'web1_nts'}),
        ('web1_nonts', set(), {'web1_nts'}),
        ('bonus_nolimit', set(), {'border_ratelimit'}),
        (None, {'border'}, {'border_sources', 'border_synced', 'border_falseticker'}),
    ])
    def test_one_thing_wrong(self, lab, data, tmp_pub_dir, variant, removed, lost):
        features = (ALL_FEATURES - removed) | ({variant} if variant else set())
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=features)
        assert _lost(grade) == lost

    @pytest.mark.parametrize('fixed, score', [
        (set(), 0), ({'legacy_daemon'}, 3), ({'legacy_daemon', 'legacy_network'}, 6), ({'legacy'}, 12)])
    def test_legacy_step_by_step(self, lab, data, tmp_pub_dir, fixed, score):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=fixed, answers=None)
        assert _parts(grade)['part6'] == score

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        false_name, unsync_name = data.public_by_role('false'), data.public_by_role('unsync')
        h1, h2, h5, hb = (_form_hash(grade, f) for f in ('delay', 'false_server', 'nts_port', 'kod'))
        extra = {h1: {'delay': f" {data.exchange_delay} ms", 'offset': f"{data.exchange_offset}".replace('-', '−'),
                      'stratum': '3', 'port': '123', 'epoch': '1900', 'precision': str(data.gps_precision)},
                 h2: {'false_server': false_name.upper(), 'false_offset': f"{data.false_offset + 0.6:.1f}".replace('.', ','),
                      'unsync_server': str(getattr(data.ips, unsync_name).ip)},
                 h5: {'nts_port': '4460'},
                 hb: {'kod': 'Kiss-o’-Death'}}
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None, extra=extra)
        assert _lost(grade) & set(FORM_ELEMENTS) == set()
        # the sign of the falseticker's offset counts, one second of tolerance
        extra[h2]['false_offset'] = str(-data.false_offset)
        extra[h1]['offset'] = str(data.exchange_offset + 1)
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None, extra=extra)
        assert _lost(grade) & set(FORM_ELEMENTS) == {'answer_false_offset', 'answer_offset'}

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        fields = {f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', None) or []}
        cheat = grade.get_cheat_answers('final')
        assert {name for answers in cheat.values() for name in json.loads(answers)} == fields
        for part, state in SOLVE_STATE.items():
            solve = grade.get_cheat_answers(state) or {}
            names = {name for answers in solve.values() for name in json.loads(answers)}
            assert names == {e.removeprefix('answer_') for e, p in FORM_ELEMENTS.items() if p == part}, part


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _all_texts(grade, ns):
    texts = [('informations', _text(ns.informations))]
    for q in grade.get_questions_ordered():
        texts.append((_text(q.title), _text(q.description)))
    for e in grade.get_grade_list():
        texts.append((str(e.title), _text(e.description) if e.description else ''))
    return texts


def _instructor_literals():
    """The tr() literals written inside the instructor(...) calls (removed with them by strip-instructor)."""
    import ast
    literals = []
    for node in ast.walk(ast.parse(_LAB_PATH.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'instructor':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'id', '') == 'tr' and sub.args \
                        and isinstance(sub.args[0], ast.Constant):
                    literals.append(sub.args[0].value)
    return literals


class TestTexts:
    def test_translations(self, lab, data, tmp_pub_dir):
        """The texts are French with every one translated in _TRANSLATIONS['en'] (the markup kept: checked for
        every lab of the directory by test_draft_misc_translations.py), the instructor texts included."""
        import ast
        import check_sre_translations as cst
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == cst.get_tr_strings(ast.parse(_LAB_PATH.read_text())) and all(english.values())
        literals = _instructor_literals()
        assert len(literals) == 10 and set(literals) <= set(english)
        assert sum(v.lstrip().startswith(('**Solution.**', '**For the instructor.**')) for v in english.values()) == 8
        assert lab.title.resolve('en') == "NTP and chrony: time synchronisation"
        for state in [f'solve_{part}' for part in PARTS] + ['final']:
            description = getattr(lab.NetScheme, state)._sre_state_description
            assert _text(description, 'en') != _text(description, 'fr'), state
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert has_instructor(fr) and has_instructor(en) and fr != en, _text(q.title)
            assert '**Solution.**' in en or '**For the instructor.**' in en, _text(q.title)
            markdown_to_html(en, show_instructor=True)

    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 8
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 8 and 'informations' not in with_fragment

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!@@)(?<!\{)\{[a-z_0-9]+(:[^}]*)?\}(?!\})", text), where
            assert '@@{{' not in text, where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations, resolve_text
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'why', 'hierarchy', 'packet', 'selection', 'chrony', 'container', 'chronyc', 'serve', 'keys', 'nts',
            'security', 'leap', 'cheatsheet']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets.srv.network_address), data.key_secret, 'Partie 1', 'legacy', 'cam1',
                      f"ntp1.{lab.PUBLIC_DOMAIN}", lab.hms(data.t1)):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        questions = [_text(q.description) for q in g0.get_questions_ordered()]
        first = questions[0]
        for value in (str(data.nets.wan), str(data.ips.ntp1.ip), str(data.ips.gps.ip), data.key_secret,
                      f"**{data.key_id}**"):
            assert value in first, value
        everything = "\n".join(questions)
        for value in (lab.hms(data.t1), lab.hms(data.t4), str(data.nets.lan), str(data.nets.iot), str(data.nets.dmz)):
            assert value in everything, value
        # the roles of the public servers, the answers and the faults are for the instructor only
        for value in (f"**{data.exchange_delay} ms**", f"**{data.exchange_offset} ms**", f"{data.false_offset:+d} s",
                      f"precision {data.gps_precision}", 'faux-ticker (', 'port 1123', 'noselect', 'minsources 2',
                      'maxdistance 0.00001', 'serveur gps'):
            assert value not in everything, value
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        with_solutions = "\n".join(_text(q.description) for q in g1.get_questions_ordered())
        for value in (f"**{data.exchange_delay} ms**", f"**{data.exchange_offset} ms**", f"{data.false_offset:+d} s",
                      f"precision {data.gps_precision}", 'faux-ticker ('):
            assert value in with_solutions, value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['delay', 'offset', 'stratum', 'port', 'epoch', 'precision', 'false_server', 'false_offset',
                         'unsync_server', 'nts_port', 'kod']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == len(re.findall(rb'instructor\(\s*tr\(', source)) == 9 and result.warnings == []
        assert b'**Solution' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'ntp_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('ntp_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert not set(kept) & set(_instructor_literals())
        assert len(kept) == len(lab._TRANSLATIONS['en']) - len(set(_instructor_literals()))
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (81, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|serveur|horloge|cle|depannage|decalage|'
                            r'delai|strate|reponse)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(data.faults) + list(data.roles)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        assert 'initial' in names and 'final' in names and 'solve_part6' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
