"""Offline tests of the Nagios lab (lab/sre/_DRAFT_misc/nagios.py): the data, the topology, the
state ops (`initial`, the incidents and `repair`, the whole solution of `final`, every command on
one line), the multi-pass grading contract with synthetic outputs (nothing done: 0, everything
done: 100, the solution stopped after each part earns the parts done and nothing else, a few
scoring details), the instructor texts, the numbered course, the stripped lab file and the English
identifiers.

No Docker: a small model of Nagios (object files resolved like Nagios does — templates, groups,
services expanded per host —, the states of the forced checks, the NRPE agents and the plugin of
db1) answers the grader's commands in the formats of the real tools (the fixtures of
tests/mock_data/nagios/ show them).

The archives of tests/mock_data/nagios/lab/ are real evaluations of one running project (z04,
2026-11-11: untouched, after `final`, during each incident, repaired): TestRealEvaluations replays
what the grader's commands really printed.
"""
import datetime
import importlib.util
import json
import re
import shlex
import sys
from dataclasses import dataclass
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

import nagios as ng  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'nagios.py'
_ARCHIVES = _REPO / 'tests' / 'mock_data' / 'nagios' / 'lab'
T0 = 1794431055
IFINDEX = "145"
PARTS = {'part1': 10, 'part2': 16, 'part3': 18, 'part4': 16, 'part5': 8, 'part6': 12, 'part7': 12, 'part8': 8}
# without the typed answers (part 1 is only that; two fields in part 5, one in part 7)
BEHAVIOUR = {'part1': 0, 'part2': 16, 'part3': 18, 'part4': 16, 'part5': 6, 'part6': 12, 'part7': 11, 'part8': 8}
# what Debian's packages define (monitoring-plugins, nagios-nrpe-plugin), as Nagios loads them
STOCK_CFG = r"""
define command {
    command_name    check-host-alive
    command_line    /usr/lib/nagios/plugins/check_ping -H '$HOSTADDRESS$' -w 5000,100% -c 5000,100% -p 1
}
define command {
    command_name    check_ping
    command_line    /usr/lib/nagios/plugins/check_ping -H '$HOSTADDRESS$' -w '$ARG1$' -c '$ARG2$'
}
define command {
    command_name    check_ssh
    command_line    /usr/lib/nagios/plugins/check_ssh '$HOSTADDRESS$'
}
define command {
    command_name    check_tcp
    command_line    /usr/lib/nagios/plugins/check_tcp -H '$HOSTADDRESS$' -p '$ARG1$' '$ARG2$'
}
define command {
    command_name    check_nrpe
    command_line    /usr/lib/nagios/plugins/check_nrpe -H $HOSTADDRESS$ -c $ARG1$
}
"""
DEBIAN_NRPE = ("allowed_hosts=127.0.0.1,::1\n"
               "command[check_users]=/usr/lib/nagios/plugins/check_users -w 5 -c 10\n"
               "command[check_load]=/usr/lib/nagios/plugins/check_load -r -w .15,.10,.05 -c .30,.25,.20\n")


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nagios_lab_under_test', _LAB_PATH)
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
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


# ---------------------------------------------------------------------------
# a model of Nagios: object files resolved the way Nagios does
# ---------------------------------------------------------------------------


def resolve_objects(*sources: str):
    """[(kind, block)] of what Nagios would load from object files: `use` chains followed,
    templates (`register 0`) dropped, a service per host of `host_name` lists and of
    `hostgroup_name`, group members collected from `hostgroups` / `servicegroups`."""
    raw = [b for text in sources for b in ng.parse_blocks(text)]
    templates = {(kind, b['name']): b for kind, b in raw if 'name' in b}

    def inherited(kind, block):
        merged = {}
        if block.get('use'):
            merged.update(inherited(kind, templates[(kind, block['use'])]))
        merged.update(block)
        return merged

    objects = []
    for kind, block in raw:
        if block.get('register') == '0':
            continue
        full = {k: v for k, v in inherited(kind, block).items() if k not in ('use', 'name', 'register')}
        objects.append((kind, full))
    hosts = {b['host_name']: b for k, b in objects if k == 'host'}
    members = {}
    for name, host in hosts.items():
        for group in [g.strip() for g in host.get('hostgroups', '').split(',') if g.strip()]:
            members.setdefault(group, set()).add(name)
    for k, b in objects:
        if k == 'hostgroup':
            members.setdefault(b['hostgroup_name'], set()).update(
                m.strip() for m in b.get('members', '').split(',') if m.strip())
            b['members'] = ','.join(sorted(members[b['hostgroup_name']]))
    services, others = [], []
    for kind, block in objects:
        if kind != 'service':
            others.append((kind, block))
            continue
        names = [n.strip() for n in block.get('host_name', '').split(',') if n.strip()]
        for group in [g.strip() for g in block.get('hostgroup_name', '').split(',') if g.strip()]:
            names += sorted(members.get(group, ()))
        for name in names:
            one = {k: v for k, v in block.items() if k != 'hostgroup_name'}
            one['host_name'] = name
            services.append(('service', one))
    for kind, block in others:
        if kind == 'servicegroup':
            flat = []
            for _, s in services:
                if block['servicegroup_name'] in [g.strip() for g in s.get('servicegroups', '').split(',')]:
                    flat += [s['host_name'], s['service_description']]
            block['members'] = ','.join(flat)
    return others + services


def render_cache(objects) -> str:
    return "".join("define %s {\n%s\t}\n" % (kind, "".join(f"\t{k}\t{v}\n" for k, v in block.items()))
                   for kind, block in objects)


def queue_plugin(value, warn, crit, variant='reference'):
    """(line, rc) of the queue plugin for a file holding *value* (None: missing file)."""
    if warn is None or crit is None:
        return "QUEUE UNKNOWN - seuil -w absent ou invalide", 3
    warn, crit = int(warn), int(crit)
    if value is None or not str(value).isdigit():
        if variant == 'no_unknown':
            return f"QUEUE OK - 0 travaux en attente | queue=0;{warn};{crit};0", 0
        return "QUEUE UNKNOWN - fichier illisible ou invalide", 3
    n = int(value)
    perf = f"queue={n};{warn};{crit};0"
    over = (lambda a, b: a > b) if variant == 'strict' else (lambda a, b: a >= b)
    if over(n, crit):
        return f"QUEUE CRITICAL - {n} travaux en attente | {perf}", 2
    if over(n, warn):
        return f"QUEUE WARNING - {n} travaux en attente | {perf}", 1
    return f"QUEUE OK - {n} travaux en attente | {perf}", 0


@dataclass
class Done:
    """How far the student went (parts 2 to 8 of the reference solution) and what goes wrong."""
    parts: int = 8              # the objects of the solution up to that part
    nagios_running: bool = True
    nrpe: bool = True           # the NRPE files of the solution on web1 / db1 (parts >= 4)
    nrpe_whole_lan: bool = False  # allowed_hosts opened to every machine of the lan
    plugin: str = 'reference'   # 'reference', 'strict' (> instead of >=), 'no_unknown', or '' (no plugin)
    wrong_ifindex: bool = False
    stock_templates: bool = False   # Debian's five-minute templates instead of the lab's


class Scenario:
    def __init__(self, lab, ns, done: Done):
        self.lab, self.ns, self.d, self.done = lab, ns, ns.data, done
        d = self.d
        self.ip = {m: str(getattr(d.ips, m).ip) for m in ('monitor', 'web1', 'db1', 'probe')}
        self.router_ip = str(d.ips.router_lan.ip)
        self.objects = self._load()

    # -- objects ----------------------------------------------------------------------

    def _load(self):
        lab, done = self.lab, self.done
        sources = [STOCK_CFG, ng.render_lab_templates(lab.HOST_TEMPLATE, lab.SERVICE_TEMPLATE)]
        if done.parts >= 2:
            cfg = self.ns._solution_lab_cfg(done.parts, ifindex="7" if done.wrong_ifindex else IFINDEX)
            if done.stock_templates:
                cfg = cfg.replace("check_interval", "check_interval_unused")
                sources[1] = sources[1].replace("0.5", "5").replace("0.25", "1")
            sources.append(cfg)
        return resolve_objects(*sources)

    def _service(self, host, description):
        return next((b for k, b in self.objects if k == 'service' and b['host_name'] == host
                     and b['service_description'] == description), None)

    def _command_line(self, block, host):
        name, args = ng.split_check_command(block.get('check_command'))
        line = next((b['command_line'] for k, b in self.objects if k == 'command' and b['command_name'] == name), '')
        address = self.router_ip if host == 'router' else self.ip[host]
        return ng.expand_command_line(line, args, {'USER1': ng.PLUGIN_DIR, 'HOSTADDRESS': address, 'HOSTNAME': host})

    # -- NRPE and the plugin ------------------------------------------------------------

    def _nrpe_file(self, machine):
        if not (self.done.nrpe and self.done.parts >= 4):
            return DEBIAN_NRPE
        text = self.ns._solution_nrpe_conf(machine)
        if self.done.parts < 6:
            text = "".join(line for line in text.splitlines(True) if 'check_queue' not in line)
        if self.done.nrpe_whole_lan:
            text = text.replace(f"allowed_hosts=127.0.0.1,{self.ip['monitor']}",
                                f"allowed_hosts=127.0.0.1,{self.ip['monitor']},{self.ip['probe']}")
        return DEBIAN_NRPE + text

    def _plugin_exists(self):
        return bool(self.done.plugin) and self.done.parts >= 6

    def _nrpe(self, source, machine, command):
        """(line, rc) of check_nrpe from *source* to *machine*."""
        conf = ng.parse_nrpe_config(self._nrpe_file(machine))
        if self.ip[source] not in conf['allowed_hosts']:
            return f"CHECK_NRPE: Error - Could not connect to {self.ip[machine]}: Connection reset by peer", 2
        if command is None:
            return "NRPE v4.1.0", 0
        line = conf['commands'].get(command)
        if line is None:
            return f"NRPE: Command '{command}' not defined", 3
        words = shlex.split(line)
        opt = {words[i]: words[i + 1] for i in range(len(words) - 1) if words[i].startswith('-')}
        if 'check_load' in line:
            warn, crit = opt['-w'].split(','), opt['-c'].split(',')
            perf = " ".join(f"load{n}=0.500;;;0; scaled_load{n}=0.042;{float(w):.3f};{float(c):.3f};0;"
                            for n, w, c in zip((1, 5, 15), warn, crit))
            return f"LOAD OK - scaled load average: 0.04, 0.12, 0.10 - total load average: 0.50, 1.49, 1.24|{perf}", 0
        if 'check_disk' in line:
            return "DISK OK - free space: / 38342MiB (47% inode=-);| /=44046483456B;73014444032;79027398246;0;85899345920", 0
        if 'check_procs' in line:
            return f"PROCS OK: 1 process with command name '{opt['-C']}' | procs=1;;1:;0;", 0
        if 'check_queue' in line:
            if not self._plugin_exists():
                return "NRPE: Unable to read output", 3
            return queue_plugin(self.d.queue_value, opt.get('-w'), opt.get('-c'), self.done.plugin)
        return "USERS OK - 0 users currently logged in |users=0;5;10;0", 0

    # -- states -------------------------------------------------------------------------

    def _service_result(self, host, block):
        """(state, output, performance data) of one forced check."""
        d, description = self.d, block['service_description']
        line = self._command_line(block, host)
        if description == 'PING':
            return 0, "PING OK - Packet loss = 0%, RTA = 0.05 ms", "rta=0.05ms;100;500;0 pl=0%;20;60;0"
        if description == 'SSH':
            return 0, "SSH OK - OpenSSH_9.2p1 Debian-2+deb12u10 (protocol 2.0)", "time=0.006s;;;0;10"
        if description == 'HEALTH':
            if d.health_token in line and self.lab.HEALTH_PATH in line:
                return 0, "HTTP OK: HTTP/1.1 200 OK - 271 bytes in 0.001 second response time", "time=0.0006s;;;0;10"
            return 2, "HTTP CRITICAL: HTTP/1.1 200 OK - string not found", ""
        if description == 'DB':
            if f"-p '{d.db_port}'" in line or f"-p {d.db_port}" in line:
                return 0, f"TCP OK - 0.000 second response time on {self.ip['db1']} port {d.db_port}", "time=0.0002s;;;0;10"
            return 2, f"connect to address {self.ip['db1']} and port 1: Connection refused", ""
        if description == 'IF-DMZ':
            if f"{self.lab.IF_OPER_STATUS}.{IFINDEX} " in line + " ":
                return 0, "SNMP OK - ifOperStatus 1", "ifOperStatus=1;;1:1"
            return 3, "External command error: Error in packet", ""
        if 'check_nrpe' in line:
            command = line.split(' -c ')[-1].strip()
            text, rc = self._nrpe('monitor', host, command)
            output, _, perf = text.partition('|')
            return rc, output.strip(), perf.strip()
        return 3, "(No output on stdout)", ""

    def _status(self):
        done = self.done
        if not done.nagios_running:
            # the file of the last run is still there: everything checked long ago
            stamp = T0 - 5000
        else:
            stamp = T0 + 1
        blocks = ["info {\n\tcreated=%d\n\tversion=4.4.6\n\t}\n" % (T0 + 8), "programstatus {\n\tnagios_pid=433\n\t}\n"]
        for kind, block in self.objects:
            if kind == 'host':
                blocks.append("hoststatus {\n\thost_name=%s\n\thas_been_checked=1\n\tcheck_type=0\n\tcurrent_state=0\n"
                              "\tplugin_output=PING OK - Packet loss = 0%%, RTA = 0.05 ms\n\tlast_check=%d\n\t}\n"
                              % (block['host_name'], stamp))
            elif kind == 'service':
                host, description = block['host_name'], block['service_description']
                if block.get('active_checks_enabled') == '0':
                    accepted = block.get('passive_checks_enabled', '1') == '1' and done.nagios_running
                    state, output, perf, check_type = 0, "", "", 1
                    if accepted:
                        output = f"BACKUP OK - {self.lab.EVAL_AUTHOR} {self.d.probe_token}"
                    checked = 1 if accepted else 0
                else:
                    state, output, perf = self._service_result(host, block)
                    check_type, checked = 0, 1
                blocks.append("servicestatus {\n\thost_name=%s\n\tservice_description=%s\n\thas_been_checked=%d\n"
                              "\tcheck_type=%d\n\tcurrent_state=%d\n\tplugin_output=%s\n\tperformance_data=%s\n"
                              "\tlast_check=%d\n\t}\n" % (host, description, checked, check_type, state, output,
                                                         perf, stamp if checked else 0))
        return "".join(blocks) + "===RC 0\n"

    def _contact_notified(self):
        """True when the custom notifications of the evaluation reach the on-call contact."""
        lab = self.lab
        contact = next((b for k, b in self.objects if k == 'contact' and b.get('contact_name') == lab.CONTACT), None)
        db = self._service('db1', 'DB')
        return (self.done.nagios_running and contact is not None and db is not None
                and lab.CONTACTGROUP in db.get('contact_groups', ''))

    # -- dispatch -----------------------------------------------------------------------

    def __call__(self, machine, command):
        d, done, lab = self.d, self.done, self.lab
        if command.startswith(f"f={ng.COMMAND_FILE}; n=$(date +%s); "):
            return f"===T0 {T0}\nwritten={'0' if done.nagios_running else 'nopipe'}\n===RC 0\n", 0
        if command == ng.objects_cmd():
            return render_cache(self.objects) + "===RC 0\n", 0
        if command == ng.status_cmd(lab.STATUS_WAIT):
            return self._status(), 0
        if command == ng.nrpe_config_cmd():
            return self._nrpe_file(machine) + "===RC 0\n", 0
        if command.startswith(f"{ng.PLUGIN_DIR}/check_nrpe -H "):
            words = command.split(' 2>&1')[0].split()
            target = {v: k for k, v in self.ip.items()}[words[2]]
            name = words[words.index('-c') + 1] if '-c' in words else None
            line, rc = self._nrpe(machine, target, name)
            return f"{line}\n===RC {rc}\n", 0
        if command == f"cat /sys/class/net/{lab.ROUTER_DMZ_IF}/ifindex{ng.RC_SUFFIX}":
            return f"{IFINDEX}\n===RC 0\n", 0
        if command == f"cat {lab.QUEUE_FILE}{ng.RC_SUFFIX}":
            return f"{d.queue_value}\n===RC 0\n", 0
        if lab.QUEUE_PLUGIN in command and 'runuser -u nagios' in command:
            if not self._plugin_exists():
                return f"runuser: failed to execute {lab.QUEUE_PLUGIN}: No such file or directory\n===RC 1\n", 0
            has_thresholds = ' -w 10 -c 20' in command
            m = re.search(r"echo (\S+) > \$f", command)
            value = shlex.split(m.group(1))[0] if m else (None if '/nonexistent' in command else d.queue_value)
            line, rc = queue_plugin(value, 10 if has_thresholds else None, 20 if has_thresholds else None, done.plugin)
            return f"{line}\n===RC {rc}\n", 0
        if command == ng.notification_log_cmd(f"{lab.EVAL_AUTHOR};{d.probe_token}"):
            lines = [f"[{T0 - 900}] SERVICE NOTIFICATION: {lab.CONTACT};db1;DB;CUSTOM (OK);notify-service-by-sms;"
                     f"TCP OK;{lab.EVAL_AUTHOR};{d.probe_token}"] if self._contact_notified() else []
            if self._contact_notified():
                lines += [f"[{T0}] SERVICE NOTIFICATION: {lab.CONTACT};db1;DB;CUSTOM (OK);notify-service-by-sms;"
                          f"TCP OK - 0.000 second response time;{lab.EVAL_AUTHOR};{d.probe_token}",
                          f"[{T0}] HOST NOTIFICATION: {lab.CONTACT};db1;CUSTOM (UP);notify-host-by-sms;"
                          f"PING OK - Packet loss = 0%;{lab.EVAL_AUTHOR};{d.probe_token}"]
            return "\n".join(lines) + "\n===RC 0\n", 0
        if command == ng.sms_outbox_cmd():
            if not self._contact_notified():
                return f"tail: cannot open '{ng.SMS_OUTBOX}' for reading: No such file or directory\n===RC 1\n", 0
            return (f"{T0 - 900}\t{d.oncall_pager}\tCUSTOM db1/DB OK - old\n"
                    f"{T0}\t{d.oncall_pager}\tCUSTOM db1/DB OK - TCP OK - 0.000 second response time\n"
                    f"{T0}\t{d.oncall_pager}\tCUSTOM db1 UP - PING OK - Packet loss = 0%\n===RC 0\n"), 0
        return "", 0          # diagnostics


def _simulate(lab, data, tmp_pub_dir, done=None, instructor_mode=False, cheat=True, module=None):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  Every test is registered
    on the first pass and the set never changes (the commands depend on the lab data only)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    lab = module or lab
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    scenario = Scenario(lab, ns, done if done is not None else Done())
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if previous is None:
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == previous, "the registered tests changed between two passes"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = scenario(m, key[0])
        step += 1
    return grade, ns


def _replay(lab, tag, answers=True, mutate=None):
    """Multi-pass grade() like run_tests(), every command answered by what the archive *tag*
    recorded for it: returns (grade, data).  *mutate(machine, command, (out, code))* may change an
    answer; *answers* False leaves the forms empty.

    To capture the archives again: start the lab on a Docker host, run `sre eval` in each
    situation (untouched, after `sre state … final` + the cheat answers, after `incident_db`,
    after `incident_router`, after `repair`) and copy the archive of each evaluation to
    tests/mock_data/nagios/lab/<situation>.zst."""
    raw = read_archive(str(_ARCHIVES / f"{tag}.zst"))
    stored = json.loads(raw['data_json'])
    stored['__type__'] = f"{lab.__name__}.Data"      # the archive names the module of the running lab
    data = lab.Data.from_json(json.dumps(stored))
    recorded = {key: {cmd: result for (cmd, _timeout), result in cmds.items()} for key, cmds in raw['tests'].items()}
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if previous is None:
            if answers:
                grade._answers = dict(raw.get('answers') or {})
        else:
            assert current == previous, "the registered tests changed between two passes"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    assert key[0] in recorded.get((m, s), {}), \
                        f"not in the archive {tag!r}: {m} step {s}: {key[0][:140]}"
                    result = tuple(recorded[(m, s)][key[0]])
                    cmds[key] = mutate(m, key[0], result) if mutate else result
        step += 1
    return grade, data


def _regrade(grade):
    grade.reset_before_grade()
    grade.grade()
    return _by_title(grade)


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _by_part(grade):
    totals = {}
    for e in grade.get_grade_list():
        got, maximum = totals.get(str(e.grade_part), (0, 0))
        totals[str(e.grade_part)] = (got + e.grade, maximum + e.max_grade)
    return totals


def _missing(grade):
    return sorted(str(e.title) for e in grade.get_grade_list() if e.grade != e.max_grade)


def _set_answer(grade, field, value):
    for q in grade.get_questions_ordered():
        if any(f['name'] == field for f in (getattr(q, 'fields', None) or [])):
            form = json.loads(grade._answers[q.question_hash])
            form[field] = value
            grade._answers[q.question_hash] = json.dumps(form)
            return
    raise AssertionError(f"no form field {field}")


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


# ---------------------------------------------------------------------------
# data, topology, the model itself
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()

    def test_values(self, lab, data):
        d = data
        assert re.fullmatch(r'[0-9a-f]{8}', d.health_token) and d.health_token != d.probe_token
        assert d.db_port in (3306, 5432, 1521, 27017) and 7000 <= d.closed_port <= 7999
        assert d.queue_value < d.queue_warn < d.queue_crit            # the queue is OK at the start
        assert re.fullmatch(r'\d+\.0,\d+%', d.ping_warn) and re.fullmatch(r'\d+\.0,\d+%', d.ping_crit)
        assert len(d.load_warn.split(',')) == 3 and len(d.load_crit.split(',')) == 3
        assert d.disk_crit < d.disk_warn and d.freshness in (120, 180, 240)
        assert re.fullmatch(r'06\d{8}', d.oncall_pager) and d.snmp_location.isascii()
        assert not d.nets.lan.overlaps(d.nets.dmz)
        assert all(getattr(d.ips, m) in d.nets.lan for m in ('router_lan', 'monitor', 'pc', 'probe'))
        assert all(getattr(d.ips, m) in d.nets.dmz for m in ('router_dmz', 'web1', 'db1'))
        # the tokens go through the command pipe of Nagios: plain characters only
        ng.external_commands_cmd([ng.external_command('X', d.probe_token, d.health_token)])


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'monitor', 'pc', 'router', 'web1', 'db1', 'probe'}
        for m in lab.SYSTEMD_MACHINES:
            machine = ns.get_machine(m)
            assert machine.privileged and machine.entrypoint == '/sbin/init' and not machine.hidden
            assert machine.image == params.sre_docker_image('monitoring')
        pc = ns.get_machine('pc')
        assert pc.bridged and pc.x11_host and pc.image == params.default_docker_image
        assert not ns.get_machine('router').allow_connection and not ns.get_machine('router').privileged
        probe = ns.get_machine('probe')
        assert probe.hidden and not probe.allow_connection and probe.image == params.sre_docker_image('monitoring')
        assert lab.allow_user_states is True and lab.export_kathara_project is False

    def test_image_is_written_literally(self):
        assert _LAB_PATH.read_text().count('"image": sre_docker_image("monitoring")') >= 3

    def test_routes(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        d = data
        assert str(ns.net_config['monitor'][0][1][0][1]) == str(d.ips.router_lan.ip)
        assert str(ns.net_config['web1'][0][1][0][1]) == str(d.ips.router_dmz.ip)
        # pc is bridged (Docker's default route): only a route to the dmz
        assert ns.net_config['pc'][0][1] == [(d.nets.dmz, d.ips.router_lan.ip)]


class TestModel:
    """The resolver of the tests behaves like Nagios on the real session of the fixtures."""

    def test_reference_objects_resolve_like_the_real_cache(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        objects = ng.parse_objects_cache(render_cache(resolve_objects(
            STOCK_CFG, ng.render_lab_templates(), ns._solution_lab_cfg(8, ifindex=IFINDEX))))
        real = ng.parse_objects_cache((_REPO / 'tests' / 'mock_data' / 'nagios' / 'objects_final.cache').read_text())
        assert objects.hostgroup_members(lab.HOSTGROUP) == real.hostgroup_members('dmz-servers') == {'web1', 'db1'}
        assert objects.servicegroup_members(lab.SERVICEGROUP) == real.servicegroup_members('business')
        assert objects.contactgroup_members(lab.CONTACTGROUP) == {'oncall'}
        ours = {(b['host_name'], b['service_description']) for b in objects.of_kind('service')}
        theirs = {(b['host_name'], b['service_description']) for b in real.of_kind('service')
                  if b['host_name'] != 'localhost'}
        assert ours == theirs == set(lab.ACTIVE_SERVICES) | {lab.PASSIVE_SERVICE}
        for host in ('web1', 'db1'):
            for key in ('parents', 'contact_groups', 'check_command', 'max_check_attempts'):
                assert objects.host(host)[key] == real.host(host)[key]
            assert ng.number(objects.host(host), 'check_interval') == ng.number(real.host(host), 'check_interval')
        assert ng.options_set(objects.service('db1', 'DB')['notification_options']) == {'c', 'r'}
        assert objects.service('db1', 'BACKUP')['active_checks_enabled'] == '0'

    def test_queue_plugin_model_matches_the_reference_script(self):
        assert queue_plugin(5, 10, 20) == ("QUEUE OK - 5 travaux en attente | queue=5;10;20;0", 0)
        assert queue_plugin(10, 10, 20)[1] == 1 and queue_plugin(20, 10, 20)[1] == 2
        assert queue_plugin('abc', 10, 20)[1] == 3 and queue_plugin(None, 10, 20)[1] == 3
        assert queue_plugin(5, None, None)[1] == 3
        assert queue_plugin(10, 10, 20, 'strict')[1] == 0


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        d = data
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        for m in ns.get_machine_names():
            hosts = _files(ops, 1, m)['/etc/hosts']
            assert f"{d.ips.monitor.ip}\tmonitor\t" in hosts and f"{d.ips.router_lan.ip}\trouter\t" in hosts
            assert str(d.ips.probe.ip) not in hosts
            assert ('/etc/resolv.conf' in _files(ops, 1, m)) == (m != 'pc')
        # monitor: Nagios tuned, the fast templates, the SMS gateway, the CGI module; started at step 2
        cmds, files = _cmds(ops, 1, 'monitor'), _files(ops, 1, 'monitor')
        assert any('status_update_interval=5' in c and 'service_freshness_check_interval=15' in c for c in cmds)
        assert any('a2enmod cgi' in c and 'chown nagios:nagios /var/spool/sms' in c for c in cmds)
        templates = dict(ng.parse_blocks(files[lab.TEMPLATES_CFG]))
        assert templates['host']['name'] == lab.HOST_TEMPLATE and templates['service']['name'] == lab.SERVICE_TEMPLATE
        assert files[ng.SMS_SEND].startswith('#!/bin/sh') and '/etc/nagios4/objects/localhost.cfg' in files
        assert lab.LAB_CFG not in files
        assert _cmds(ops, 2, 'monitor') == ['systemctl restart apache2 nagios4']
        # web1 and db1
        assert _files(ops, 1, 'web1')[f'/var/www/html{lab.HEALTH_PATH}'] == f"status=ok token={d.health_token}\n"
        assert 'systemctl start nginx ssh nagios-nrpe-server' in _cmds(ops, 1, 'web1')
        db1 = _files(ops, 1, 'db1')
        assert f"ExecStart={ng.LABDB_SCRIPT} {d.db_port}\n" in db1[ng.LABDB_UNIT] and db1[lab.QUEUE_FILE] == f"{d.queue_value}\n"
        assert lab.QUEUE_PLUGIN not in db1 and not any('nrpe.d' in name for name in db1)
        # router: an SNMP agent started without systemd
        assert f"rocommunity {d.snmp_community} default\n" in _files(ops, 1, 'router')['/etc/snmp/snmpd.conf']
        assert not any('systemctl' in c for c in _cmds(ops, 1, 'router'))

    def test_incidents_and_repair(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert _cmds(_state_ops(ns, 'incident_db'), 1, 'db1') == ['systemctl stop labdb']
        router = _cmds(_state_ops(ns, 'incident_router'), 1, 'router')
        assert len(router) == 1 and 'hook input priority -300; policy drop;' in router[0]
        assert 'hook forward priority -300; policy drop;' in router[0] and "\n" not in router[0]
        repair = _state_ops(ns, 'repair')
        assert 'systemctl start labdb' in _cmds(repair, 1, 'db1')
        assert _files(repair, 1, 'db1')[lab.QUEUE_FILE] == f"{data.queue_value}\n"
        assert any(f'nft delete table inet {lab.INCIDENT_TABLE}' in c for c in _cmds(repair, 1, 'router'))
        for name in ('incident_db', 'incident_router', 'repair'):
            assert getattr(lab.NetScheme, name)._sre_state_user_allowed is True
        assert lab.NetScheme.final._sre_state_user_allowed is False

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        d = data
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        for m in lab.SERVERS:
            conf = ng.parse_nrpe_config(_files(ops, 1, m)[f'{ng.NRPE_D}/lab.cfg'])
            assert conf['allowed_hosts'] == ['127.0.0.1', str(d.ips.monitor.ip)]
            assert conf['commands']['check_load'].endswith(f'-r -w {d.load_warn} -c {d.load_crit}')
            assert conf['commands']['check_disk'].endswith(f'-w {d.disk_warn}% -c {d.disk_crit}% -p /')
            assert conf['commands']['check_procs'].endswith(f'-C {lab.WATCHED_PROCESS[m]}')
            assert ('check_queue' in conf['commands']) == (m == 'db1')
            assert 'systemctl restart nagios-nrpe-server' in _cmds(ops, 1, m)
        assert _files(ops, 1, 'db1')[lab.QUEUE_PLUGIN] == ng.render_check_queue(lab.QUEUE_FILE)
        cfg = _files(ops, 2, 'monitor')[lab.LAB_CFG]
        assert '__IFINDEX__' in cfg and cfg == ns._solution_lab_cfg()
        last = _cmds(ops, 2, 'monitor')[-1]
        assert 's/__IFINDEX__/$idx/' in last and last.endswith('&& systemctl restart nagios4')
        assert f".1.3.6.1.2.1.4.20.1.2.{d.ips.router_dmz.ip}" in last and f"-c {d.snmp_community} " in last

    def test_solution_stages_only_append(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        for part in (3, 4, 5, 6, 8):
            assert ns._solution_lab_cfg(part).startswith(ns._solution_lab_cfg(part - 1)), part
            assert ns._solution_added(part).startswith('define ')
        assert 'define contact {' not in ns._solution_lab_cfg(6) and 'define contact {' in ns._solution_lab_cfg(7)


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _missing(grade) == []
        assert _totals(grade) == (100, 100)
        assert _by_part(grade) == {k: (v, v) for k, v in PARTS.items()}
        assert grade.max_step == 2

    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=Done(parts=1, nrpe=False, plugin=''), cheat=False)
        assert _totals(grade) == (0, 100)

    @pytest.mark.parametrize('parts', [2, 3, 4, 5, 6, 7, 8])
    def test_solution_stopped_after_a_part(self, lab, data, tmp_pub_dir, parts):
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=Done(parts=parts), cheat=False)
        got = _by_part(grade)
        for index, (part, maximum) in enumerate(PARTS.items(), 1):
            expected = BEHAVIOUR[part] if index <= parts else 0
            assert got[part] == (expected, maximum), (part, _missing(grade))

    def test_typed_answers_alone(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=Done(parts=1, nrpe=False, plugin=''))
        got = _by_part(grade)
        assert got['part1'] == (10, 10) and got['part5'] == (2, 8) and got['part7'] == (1, 12)
        assert _totals(grade) == (13, 100)

    def test_nagios_stopped_grants_no_state(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=Done(nagios_running=False), cheat=False)
        elements = _by_title(grade)
        # what is read in the object cache and on the servers stays...
        for name in ('host_fast', 'host_parents', 'hostgroup', 'cmd_http_string', 'svc_fast', 'servicegroup',
                     'nrpe_allowed_web1', 'nrpe_probe_refused', 'plugin_ok', 'contact_oncall', 'contactgroup',
                     'notif_options', 'passive_service', 'stale_command'):
            assert elements[name].grade == elements[name].max_grade, name
        # ... the states of a file left by a previous run are not taken
        for name in ('host_router', 'host_web1', 'svc_ping', 'svc_ssh', 'svc_health', 'svc_db', 'svc_nrpe',
                     'svc_snmp_if', 'svc_snmp_threshold', 'notif_logged', 'notif_delivered', 'notif_host',
                     'passive_result'):
            assert elements[name].grade == 0, name

    @pytest.mark.parametrize('change, lost', [
        ({'nrpe': False}, {'nrpe_allowed_web1', 'nrpe_allowed_db1', 'nrpe_probe_refused', 'nrpe_cmd_load',
                           'nrpe_cmd_disk', 'nrpe_cmd_procs', 'svc_nrpe', 'svc_queue'}),
        ({'nrpe_whole_lan': True}, {'nrpe_probe_refused'}),
        ({'plugin': ''}, {'plugin_ok', 'plugin_warning', 'plugin_critical', 'plugin_unknown', 'plugin_perfdata',
                          'svc_queue'}),
        ({'plugin': 'strict'}, {'plugin_warning', 'plugin_critical'}),           # > instead of >=
        ({'plugin': 'no_unknown'}, {'plugin_unknown'}),
        ({'wrong_ifindex': True}, {'svc_snmp_if', 'svc_snmp_threshold'}),
        ({'stock_templates': True}, {'host_fast', 'svc_fast'}),
    ])
    def test_one_thing_wrong(self, lab, data, tmp_pub_dir, change, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=Done(**change))
        assert set(_missing(grade)) == lost

    def test_a_missing_plugin_is_not_a_warning(self, lab, data, tmp_pub_dir):
        # runuser exits 1 when the plugin does not exist: the state word of the output is read too
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=Done(plugin=''))
        assert _by_title(grade)['plugin_warning'].grade == 0

    def test_typed_answers(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        _set_answer(grade, 'status_file', ng.STATUS_DAT + '/')
        _set_answer(grade, 'syscontact', 'noc@corp.lab')
        _set_answer(grade, 'syslocation', data.snmp_location.upper())
        elements = _regrade(grade)
        assert all(elements[k].grade == elements[k].max_grade
                   for k in ('answer_status_file', 'answer_syscontact', 'answer_syslocation'))
        _set_answer(grade, 'rc_404', '2')
        _set_answer(grade, 'health_token', data.probe_token)
        _set_answer(grade, 'unreachable', 'down')
        elements = _regrade(grade)
        assert [elements[k].grade for k in ('answer_rc_404', 'answer_health_token', 'answer_unreachable')] == [0, 0, 0]

    def test_typed_answers_are_instructor_scope(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for element in grade.get_grade_list():
            assert (element.scope == params.EXO_EVAL_SCOPE) == str(element.title).startswith('answer_')

    def test_cheat_answers_match_the_form_fields(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        cheats = grade.get_cheat_answers('final')
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 3
        for q in forms:
            assert set(json.loads(cheats[q.question_hash])) == {f['name'] for f in q.fields}

    def test_commands(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        tests = grade.get_tests()
        assert {step for _, step in tests} == {1, 2}
        assert {m for m, _ in tests} == {'monitor', 'router', 'web1', 'db1', 'probe'}
        for (machine, step), cmds in tests.items():
            for command, _timeout in cmds:
                assert "\n" not in command and "@@@" not in command, (machine, command[:60])
        # the orders to Nagios are the first command of monitor, before anything that takes time
        first = next(iter(tests[('monitor', 1)]))[0]
        assert first.startswith(f"f={ng.COMMAND_FILE}; ")
        for host, service in lab.ACTIVE_SERVICES:
            assert f'"SCHEDULE_FORCED_SVC_CHECK;{host};{service};$n"' in first
        assert f'"PROCESS_SERVICE_CHECK_RESULT;db1;BACKUP;0;BACKUP OK - {lab.EVAL_AUTHOR} {data.probe_token}"' in first
        assert 'BACKUP;$n' not in first                      # the passive service is never force-checked
        # the plugin is tried on temporary files: the real queue file is only read
        on_db1 = [c for c, _ in tests[('db1', 1)]]
        assert sum('mktemp' in c for c in on_db1) == 6 and not any(f'> {lab.QUEUE_FILE}' in c for c in on_db1)


# ---------------------------------------------------------------------------
# real evaluations replayed
# ---------------------------------------------------------------------------

DB_INCIDENT = {'svc_db', 'nrpe_cmd_procs', 'svc_nrpe'}
ROUTER_INCIDENT = {'host_router', 'host_web1', 'host_db1', 'svc_ping', 'svc_ssh', 'svc_health', 'svc_db',
                   'nrpe_allowed_web1', 'nrpe_allowed_db1', 'nrpe_probe_refused', 'nrpe_cmd_load', 'nrpe_cmd_disk',
                   'nrpe_cmd_procs', 'svc_nrpe', 'svc_snmp_if', 'svc_snmp_threshold', 'svc_queue'}


class TestRealEvaluations:
    """What a running project really answered (tests/mock_data/nagios/lab/*.zst)."""

    def test_untouched_project(self, lab, tmp_pub_dir):
        grade, _ = _replay(lab, 'initial')
        assert _totals(grade) == (0, 100)

    @pytest.mark.parametrize('tag', ['solved', 'repaired'])
    def test_reference_solution(self, lab, tmp_pub_dir, tag):
        grade, _ = _replay(lab, tag)
        assert _missing(grade) == []
        assert _totals(grade) == (100, 100)

    def test_typed_answers_alone_are_thirteen_points(self, lab, tmp_pub_dir):
        with_answers, _ = _replay(lab, 'solved')
        without, _ = _replay(lab, 'solved', answers=False)
        assert _totals(without) == (87, 100)
        assert {t for t in _missing(without)} == {t for t in _by_title(with_answers) if t.startswith('answer_')}

    def test_database_incident(self, lab, tmp_pub_dir):
        # the stand-in database stopped: its port and its process, nothing else
        grade, _ = _replay(lab, 'incident_db')
        assert set(_missing(grade)) == DB_INCIDENT and _totals(grade) == (95, 100)
        elements = _by_title(grade)
        assert elements['nrpe_cmd_procs'].grade == 1 and elements['svc_nrpe'].grade == 3     # web1 still fine

    def test_router_incident(self, lab, tmp_pub_dir):
        # the router drops everything: what is read on monitor alone stays (objects, plugin cases
        # run on db1 by the evaluation, notifications, the passive service)
        grade, _ = _replay(lab, 'incident_router')
        assert set(_missing(grade)) == ROUTER_INCIDENT and _totals(grade) == (56, 100)

    def test_notifications_of_earlier_evaluations_do_not_count(self, lab, tmp_pub_dir):
        # 'repaired' is the ninth evaluation of the project: the log and the outbox hold the
        # notifications of the eight others, with the same token
        def older(machine, command, result):
            out, code = result
            stamps = sorted({int(m) for m in re.findall(r"^\[?(\d{10})\]?[ \t]", out, re.M)})
            if machine != 'monitor' or len(stamps) < 2 or not ('NOTIFICATION' in command or ng.SMS_OUTBOX in command):
                return result
            kept = [line for line in out.splitlines() if not re.match(rf"\[?{stamps[-1]}\]?[ \t]", line)]
            return "\n".join(kept) + "\n", code

        grade, _ = _replay(lab, 'repaired', mutate=older)
        assert set(_missing(grade)) == {'notif_logged', 'notif_delivered', 'notif_host'}

    def test_states_of_an_earlier_run_do_not_count(self, lab, tmp_pub_dir):
        # Nagios stopped: the pipe is gone, status.dat is the one of the last run
        def stopped(machine, command, result):
            if command.startswith(f"f={ng.COMMAND_FILE}; "):
                return re.sub(r"written=\S+", "written=nopipe", result[0]), result[1]
            return result

        grade, _ = _replay(lab, 'solved', mutate=stopped)
        elements = _by_title(grade)
        for name in ('host_router', 'svc_ping', 'svc_db', 'svc_nrpe', 'svc_snmp_if', 'passive_result'):
            assert elements[name].grade == 0, name
        assert elements['svc_queue'].grade == 1          # published by NRPE: yes; supervised: unknown
        for name in ('host_parents', 'hostgroup', 'servicegroup', 'nrpe_allowed_web1', 'plugin_ok', 'contact_oncall'):
            assert elements[name].grade == elements[name].max_grade, name

    def test_archives_hold_what_the_grader_asks(self, lab, tmp_pub_dir):
        raw = read_archive(str(_ARCHIVES / 'solved.zst'))
        assert {m for m, _ in raw['tests']} == {'monitor', 'router', 'web1', 'db1', 'probe'}
        first = next(cmd for (cmd, _t) in raw['tests'][('monitor', 1)] if cmd.startswith(f"f={ng.COMMAND_FILE}; "))
        out, _ = raw['tests'][('monitor', 1)][(first, next(t for (c, t) in raw['tests'][('monitor', 1)] if c == first))]
        assert ng.parse_written(out) is True and ng.parse_t0(out) > 1794000000


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 9          # the organisation + one per part
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 9 and 'informations' not in with_fragment
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        for value in (data.snmp_community, data.oncall_pager, data.ping_warn, data.load_crit, str(data.db_port),
                      str(data.freshness), lab.HOST_TEMPLATE, lab.QUEUE_PLUGIN):
            assert value in student
        # what the students must find by themselves, and the grader's token, are not given
        assert data.health_token not in student and data.probe_token not in student
        assert data.snmp_location not in student
        assert data.health_token in "\n".join(t for _, t in _all_texts(g1, ns1))

    def test_texts_are_formatted_and_render(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            plain = re.sub(r"```.*?```", "", re.sub(r"@@\{[^}]*\}@@", "", text), flags=re.S)
            assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", plain), where
            assert '@@{' not in text or where != 'informations'
            assert '</' not in plain, where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)

    def test_course_is_numbered_and_generic(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        resolved, numbering = resolve_informations(ns1.informations)
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 12)]
        assert [s.number for s in numbering.sections('fr') if s.level == 2] == ['4.1', '4.2', '5.1']
        informations = _text(resolved)
        assert '@@' not in informations and 'Organisation du TP' not in informations
        for value in (data.snmp_community, data.oncall_pager, data.health_token, str(data.ips.web1.ip)):
            assert value not in informations
        assert '## <a id="nrpe"></a>6. NRPE : exécuter des greffons sur la machine supervisée' in informations
        assert not re.search(r"^ +```", _text(ns1.informations), re.M)      # no fence inside a list item
        for q in g1.get_questions_ordered():
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            assert '@@ref' not in description.resolve('fr')

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert set(kinds) == {'health_token', 'rc_404', 'rc_string', 'rc_refused', 'status_file', 'objects_cache',
                              'command_file', 'user1', 'interval_seconds', 'syslocation', 'syscontact', 'unreachable'}
        assert kinds['unreachable']['choices'] == ['up', 'down', 'unreachable', 'pending']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 12 and result.warnings == []
        stripped = tmp_path / 'nagios_stripped.py'
        stripped.write_bytes(result.data)
        assert b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('nagios_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True, module=module)
        assert _totals(grade) == (100, 100)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        french = re.compile(r'(routeur|serveur|sonde|reseau|greffon|hote|seuil|astreinte|sauvegarde|panne)', re.I)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = list(lab.NetScheme._machine_specs) + list(lab.NetScheme._topology)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets))
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
