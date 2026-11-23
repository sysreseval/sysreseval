"""Helpers of the Ansible automation lab (lab/sre/_DRAFT_misc/ansible.py).

Named ``ansible_helpers`` and not ``ansible``: the lib directory is on ``sys.path`` of the SRE
process, a module named ``ansible`` would shadow the real package (``openldap.py`` avoids
``ldap`` the same way).

- **State side**: ``install_trace()`` copies the callback plugin ``lib/ansible_trace.py`` to the
  control node, where every ``ansible-playbook`` run loads it and appends one JSON line to
  ``TRACE_LOG``; ``local_fact_json()`` renders a local fact file.
- **Grade side**, pure parsers tested offline (``tests/test_ansible_helpers.py``):

  * the runs: ``parse_runs()`` (the JSON lines of ``TRACE_LOG``), ``iter_tasks()`` (the tasks of
    the runs matching a filter: role, module, handler, loop, run_once, delegate_to),
    ``task_done_on()`` / ``tasks_done_on()`` (a task, or any task of a filter, succeeded on every
    host given), ``idempotent_run()`` (a run where every task of a role was ok on every host given,
    nothing changed), ``normalize_action()``;
  * the inventory and the configuration: ``parse_inventory_list()`` (``ansible-inventory --list``),
    ``group_hosts()`` / ``group_children()``, ``hostvar()``, ``parse_config_dump()``
    (``ansible-config dump --only-changed``);
  * Vault and passwords: ``is_vault()``, ``crypt_check_cmd()`` / ``crypt_matches()`` (a password
    against the hash of ``/etc/shadow``, any hash type: Python 3.13 has no ``crypt`` module, the
    command calls ``libcrypt`` through ``ctypes``);
  * ``parse_users()`` (``getent passwd``), ``parse_group_line()`` (``getent group``),
    ``motd_matches()``.
"""
from __future__ import annotations

import ast
import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from SRE.lib_sre import NetScheme0

#: where the callback plugin is installed on the control node (a default callback path)
TRACE_PLUGIN_PATH = "/usr/share/ansible/plugins/callback/sre_trace.py"
#: the log the plugin appends one JSON line per ansible-playbook run to
TRACE_LOG = "/var/log/ansible-runs.jsonl"
#: the runs the grader reads (the last ones)
TRACE_TAIL = 200
#: the statuses of a host that count as a success of a task
SUCCESS = ('ok', 'changed')
#: the module names a short name resolves to outside ansible.builtin
COLLECTION_MODULES = {
    'sysctl': 'ansible.posix.sysctl',
    'authorized_key': 'ansible.posix.authorized_key',
}


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def install_trace(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Install the callback plugin and create its log (mode 0666: a run as another user than root
    is recorded too)."""
    plugin = Path(__file__).with_name('ansible_trace.py').read_text()
    net_scheme.file(machine, TRACE_PLUGIN_PATH, plugin, permissions=0o644, step=step)
    net_scheme.cmd(machine, f"touch {TRACE_LOG} && chmod 666 {TRACE_LOG}", step=step)


def local_fact_json(values: Dict[str, Any]) -> str:
    """The content of a local fact file (``/etc/ansible/facts.d/<name>.fact``, JSON, not executable:
    an executable fact file is run and its output read)."""
    return json.dumps(values, indent=2, sort_keys=True) + "\n"


def read_trace_cmd(tail: int = TRACE_TAIL) -> str:
    return f"tail -n {int(tail)} {TRACE_LOG} 2>/dev/null; true"


# ---------------------------------------------------------------------------
# the runs
# ---------------------------------------------------------------------------


def parse_runs(text: str) -> List[Dict[str, Any]]:
    """The runs of the trace log, oldest first; a line that is no run record is skipped."""
    runs = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            run = json.loads(line)
        except ValueError:
            continue
        if isinstance(run, dict) and isinstance(run.get('tasks'), list):
            runs.append(run)
    return runs


def normalize_action(action: str) -> str:
    """One name per module: ``template``, ``ansible.builtin.template`` and
    ``ansible.legacy.template`` are ``template``; ``sysctl`` is ``ansible.posix.sysctl``."""
    action = str(action or '').strip()
    for prefix in ('ansible.builtin.', 'ansible.legacy.'):
        if action.startswith(prefix):
            action = action[len(prefix):]
    return COLLECTION_MODULES.get(action, action)


def _task_matches(task: Dict[str, Any], role=None, action=None, handler=None, loop=None, run_once=None,
                  delegate_to=None) -> bool:
    if role is not None and task.get('role', '') != role:
        return False
    if action is not None:
        actions = {normalize_action(a) for a in ([action] if isinstance(action, str) else action)}
        if normalize_action(task.get('action', '')) not in actions:
            return False
    if handler is not None and bool(task.get('handler')) != handler:
        return False
    if loop is not None and bool(task.get('loop')) != loop:
        return False
    if run_once is not None and bool(task.get('run_once')) != run_once:
        return False
    if delegate_to is not None:
        targets = [delegate_to] if isinstance(delegate_to, str) else list(delegate_to)
        if task.get('delegate_to', '') not in targets:
            return False
    return True


def iter_tasks(runs: Sequence[Dict[str, Any]], **filters) -> Iterator[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """``(run, task)`` for every task of *runs* matching *filters* (``role``, ``action`` (a name or
    a list), ``handler``, ``loop``, ``run_once``, ``delegate_to`` (a name or a list); ``None``: any)."""
    for run in runs:
        for task in run.get('tasks', []):
            if isinstance(task, dict) and _task_matches(task, **filters):
                yield run, task


def task_done_on(task: Dict[str, Any], hosts: Iterable[str], statuses=SUCCESS) -> bool:
    """True when the task ended with one of *statuses* on every host of *hosts*."""
    results = task.get('hosts', {}) or {}
    hosts = list(hosts)
    return bool(hosts) and all(results.get(h) in statuses for h in hosts)


def tasks_done_on(runs: Sequence[Dict[str, Any]], hosts: Iterable[str], statuses=SUCCESS, **filters) -> bool:
    """True when every host of *hosts* has a task matching *filters* that ended with one of
    *statuses* (the hosts may have been reached by different runs)."""
    hosts = list(hosts)
    if not hosts:
        return False
    done: Set[str] = set()
    for _run, task in iter_tasks(runs, **filters):
        results = task.get('hosts', {}) or {}
        done.update(h for h in hosts if results.get(h) in statuses)
    return done.issuperset(hosts)


def hosts_of_tasks(runs: Sequence[Dict[str, Any]], statuses=SUCCESS, **filters) -> Set[str]:
    """The hosts on which a task matching *filters* ended with one of *statuses*."""
    done: Set[str] = set()
    for _run, task in iter_tasks(runs, **filters):
        done.update(h for h, s in (task.get('hosts', {}) or {}).items() if s in statuses)
    return done


def idempotent_run(runs: Sequence[Dict[str, Any]], role: str, hosts: Iterable[str], min_tasks: int = 3) -> bool:
    """True when one run applied the tasks of *role* to every host of *hosts* without changing
    anything: on each host, at least *min_tasks* tasks of the role ended ``ok`` and none ended
    ``changed``, ``failed`` or ``unreachable`` (a ``--check`` run counts: nothing would change)."""
    hosts = list(hosts)
    if not hosts:
        return False
    for run in runs:
        tasks = [t for t in run.get('tasks', []) if isinstance(t, dict) and t.get('role') == role]
        good = True
        for host in hosts:
            statuses = [t.get('hosts', {}).get(host) for t in tasks]
            statuses = [s for s in statuses if s is not None]
            if sum(1 for s in statuses if s == 'ok') < min_tasks or any(
                    s in ('changed', 'failed', 'unreachable') for s in statuses):
                good = False
                break
        if good:
            return True
    return False


# ---------------------------------------------------------------------------
# inventory and configuration
# ---------------------------------------------------------------------------


def parse_inventory_list(text: str) -> Dict[str, Any]:
    """``{'groups': {group: {'hosts': set, 'children': set}}, 'hostvars': {host: {...}}}`` from the
    JSON of ``ansible-inventory --list`` (anything before the first ``{`` is ignored: warnings);
    empty when the text is no inventory."""
    empty = {'groups': {}, 'hostvars': {}}
    text = text or ''
    start = text.find('{')
    if start < 0:
        return empty
    try:
        data, _end = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return empty
    if not isinstance(data, dict):
        return empty
    groups = {}
    for name, value in data.items():
        if name == '_meta' or not isinstance(value, dict):
            continue
        groups[name] = {'hosts': set(map(str, value.get('hosts', []) or [])),
                        'children': set(map(str, value.get('children', []) or []))}
    hostvars = (data.get('_meta') or {}).get('hostvars') or {}
    return {'groups': groups, 'hostvars': hostvars if isinstance(hostvars, dict) else {}}


def group_children(inventory: Dict[str, Any], group: str) -> Set[str]:
    return set(inventory.get('groups', {}).get(group, {}).get('children', set()))


def group_hosts(inventory: Dict[str, Any], group: str) -> Set[str]:
    """The hosts of *group*, those of its children (recursively) included."""
    groups = inventory.get('groups', {})
    hosts: Set[str] = set()
    seen: Set[str] = set()
    todo = [group]
    while todo:
        name = todo.pop()
        if name in seen or name not in groups:
            continue
        seen.add(name)
        hosts |= groups[name]['hosts']
        todo.extend(groups[name]['children'])
    return hosts


def hostvar(inventory: Dict[str, Any], host: str, name: str, default=None):
    return (inventory.get('hostvars', {}).get(host) or {}).get(name, default)


_DUMP_LINE = re.compile(r'^([A-Z][A-Z0-9_]*)\(([^)]*)\)\s*=\s*(.*)$')


def parse_config_dump(text: str) -> Dict[str, Tuple[str, Any]]:
    """``{setting: (origin, value)}`` from ``ansible-config dump --only-changed`` (text form,
    ``DEFAULT_HOST_LIST(/root/ansible/ansible.cfg) = ['/root/ansible/inventory.ini']``); the
    value is a Python literal when it parses as one, else the raw text.  ANSI colours are removed."""
    settings = {}
    for line in re.sub(r'\x1b\[[0-9;]*m', '', text or '').splitlines():
        match = _DUMP_LINE.match(line.strip())
        if not match:
            continue
        key, origin, raw = match.groups()
        try:
            value = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            value = raw.strip()
        settings[key] = (origin.strip(), value)
    return settings


def config_value(settings: Dict[str, Tuple[str, Any]], key: str, default=None):
    return settings.get(key, (None, default))[1]


def config_list(settings: Dict[str, Tuple[str, Any]], key: str) -> List[str]:
    value = config_value(settings, key)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [v.strip() for v in str(value).split(',') if v.strip()]


# ---------------------------------------------------------------------------
# Vault, accounts, files
# ---------------------------------------------------------------------------


def is_vault(text: str) -> bool:
    """True for a file encrypted by ``ansible-vault`` (header ``$ANSIBLE_VAULT;1.1;AES256``)."""
    return (text or '').lstrip().startswith('$ANSIBLE_VAULT;')


#: the marker lines of crypt_check_cmd()
CRYPT_MATCH, CRYPT_NOMATCH, CRYPT_NOUSER = 'CRYPT=match', 'CRYPT=nomatch', 'CRYPT=nouser'


def crypt_check_cmd(user: str, password: str) -> str:
    """Shell command printing ``CRYPT=match`` when *password* is the password of *user* in
    ``/etc/shadow`` (``CRYPT=nomatch`` otherwise, ``CRYPT=nouser`` without such an entry): libcrypt's
    ``crypt()`` through ``ctypes``, so every hash type of the system (``$y$`` yescrypt, ``$6$``
    sha512...) is checked.  The password and the user travel base64-encoded."""
    u = base64.b64encode(str(user).encode()).decode()
    p = base64.b64encode(str(password).encode()).decode()
    code = ("import base64,ctypes;"
            f"u=base64.b64decode('{u}').decode();p=base64.b64decode('{p}');"
            "l=ctypes.CDLL('libcrypt.so.1');l.crypt.restype=ctypes.c_char_p;"
            "l.crypt.argtypes=[ctypes.c_char_p,ctypes.c_char_p];"
            "h=[x.split(':')[1] for x in open('/etc/shadow') if x.split(':')[0]==u];"
            "r=l.crypt(p,h[0].encode()) if h and len(h[0])>2 else None;"
            "print('CRYPT=nouser' if not h else ('CRYPT=match' if r is not None and r==h[0].encode() "
            "else 'CRYPT=nomatch'))")
    return f'python3 -c "{code}"'


def crypt_matches(output: str) -> bool:
    return CRYPT_MATCH in (output or '').split()


def parse_users(text: str) -> Dict[str, Dict[str, Any]]:
    """``{name: {'uid', 'gid', 'home', 'shell'}}`` from ``getent passwd`` lines."""
    users = {}
    for line in (text or '').splitlines():
        fields = line.strip().split(':')
        if len(fields) != 7 or not fields[2].isdigit() or not fields[3].isdigit():
            continue
        users[fields[0]] = {'uid': int(fields[2]), 'gid': int(fields[3]), 'home': fields[5], 'shell': fields[6]}
    return users


def parse_group_line(text: str) -> Optional[Dict[str, Any]]:
    """``{'name', 'gid', 'members'}`` from the first ``getent group`` line of *text*, else None."""
    for line in (text or '').splitlines():
        fields = line.strip().split(':')
        if len(fields) == 4 and fields[2].isdigit():
            return {'name': fields[0], 'gid': int(fields[2]),
                    'members': {m for m in fields[3].split(',') if m}}
    return None


def motd_matches(content: str, expected: str) -> bool:
    """The motd holds exactly *expected* (blank lines and trailing spaces aside)."""
    lines = [line.rstrip() for line in (content or '').splitlines() if line.strip()]
    return lines == [line.rstrip() for line in expected.splitlines() if line.strip()]
