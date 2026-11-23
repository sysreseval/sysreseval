"""Tests of lib/ansible_helpers.py and of the callback plugin lib/ansible_trace.py (the Ansible lab).

The parsers run on outputs captured live on s16 (2026-11-23, ansible-core 2.19.11, project of
lab/sre/_DRAFT_misc/ansible.py after its `final` state: tests/mock_data/ansible/ansible_live.json)
and on small hand-written cases.  The callback plugin is driven through a stand-in ``ansible``
package (the venv has no Ansible), with result objects of both APIs: the public attributes of
2.19's ``CallbackTaskResult`` and the private ones of older ``TaskResult`` objects.
"""
import base64
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import ansible_helpers as ah  # noqa: E402

LIVE = json.loads((_REPO / 'tests' / 'mock_data' / 'ansible' / 'ansible_live.json').read_text())
DATA = LIVE['data']['data']          # the data.json of the project: {'__type__': 'Data', 'data': {...}}


def _live(label, needle, machine='control'):
    for m, _step, cmd, out, _code in LIVE[label]:
        if m == machine and needle in cmd:
            return out
    raise KeyError(needle)


@pytest.fixture(scope='module')
def runs():
    return ah.parse_runs(_live('final', 'ansible-runs.jsonl'))


# ---------------------------------------------------------------------------
# runs
# ---------------------------------------------------------------------------


class TestRuns:
    def test_parse_live_trace(self, runs):
        books = [Path(r['playbook']).name for r in runs]
        assert books == ['users.yml', 'web.yml', 'lb.yml', 'secrets.yml', 'gw.yml', 'report.yml', 'web.yml']
        assert all(r['ansible'] == '2.19.11' and r['cwd'] == '/root/ansible' and r['check'] is False for r in runs)
        first = runs[0]
        assert first['plays'] == [{'hosts': 'all', 'name': 'Accounts and rights', 'serial': []}]
        assert set(first['recap']) == {'web1', 'web2', 'lb', 'gw'}
        assert first['tasks'][0]['action'] == 'ansible.builtin.gather_facts'

    def test_bad_lines_are_skipped(self):
        text = 'garbage\n{"no": "tasks"}\n{"tasks": [], "playbook": "/x.yml"}\n{broken\n'
        assert ah.parse_runs(text) == [{'tasks': [], 'playbook': '/x.yml'}]
        assert ah.parse_runs('') == [] and ah.parse_runs(None) == []

    def test_normalize_action(self):
        assert ah.normalize_action('template') == 'template'
        assert ah.normalize_action('ansible.builtin.template') == 'template'
        assert ah.normalize_action('ansible.legacy.copy') == 'copy'
        assert ah.normalize_action('sysctl') == 'ansible.posix.sysctl'
        assert ah.normalize_action('ansible.posix.sysctl') == 'ansible.posix.sysctl'
        assert ah.normalize_action('community.general.ufw') == 'community.general.ufw'

    def test_looped_user_task(self, runs):
        nodes = ['web1', 'web2', 'lb', 'gw']
        assert ah.tasks_done_on(runs, nodes, action='user', loop=True)
        assert not ah.tasks_done_on(runs, nodes + ['client'], action='user', loop=True)
        # the user task of secrets.yml has no loop: it alone would not do
        assert not ah.tasks_done_on([runs[3]], nodes, action='user', loop=True)
        assert ah.tasks_done_on([runs[3]], nodes, action='ansible.builtin.user', loop=False)

    def test_role_handler_and_idempotence(self, runs):
        webs = ['web1', 'web2']
        assert ah.tasks_done_on(runs, webs, role='webserver', handler=True)
        assert ah.tasks_done_on(runs, webs, role='webserver', handler=False)
        assert not ah.idempotent_run(runs[:2], 'webserver', webs)        # the first run changed things
        assert ah.idempotent_run(runs, 'webserver', webs)                 # the last one did not
        assert ah.idempotent_run([runs[-1]], 'webserver', webs, min_tasks=6)
        assert not ah.idempotent_run([runs[-1]], 'webserver', webs, min_tasks=7)
        assert not ah.idempotent_run(runs, 'webserver', [])

    def test_idempotent_run_rules(self):
        def run(statuses):
            return {'tasks': [{'role': 'r', 'hosts': {'h': s}} for s in statuses]}
        assert ah.idempotent_run([run(['ok', 'ok', 'ok', 'skipped'])], 'r', ['h'])
        assert not ah.idempotent_run([run(['ok', 'ok', 'ok', 'changed'])], 'r', ['h'])
        assert not ah.idempotent_run([run(['ok', 'ok', 'failed', 'ok'])], 'r', ['h'])
        assert not ah.idempotent_run([run(['ok', 'ok'])], 'r', ['h'])

    def test_delegation_and_run_once(self, runs):
        hosts = ah.hosts_of_tasks(runs, action=['template', 'copy'], run_once=True, delegate_to=['localhost'])
        assert hosts == {'gw'}            # run_once: the first host of the play, sorted inventory order
        assert ah.tasks_done_on(runs, ['gw'], action='template') and ah.tasks_done_on(runs, ['gw'], handler=True)
        assert ah.tasks_done_on(runs, ['lb'], action='template')

    def test_iter_tasks_filters(self, runs):
        sysctl = [t for _r, t in ah.iter_tasks(runs, action='sysctl')]
        assert len(sysctl) == 1 and sysctl[0]['action'] == 'ansible.posix.sysctl' and sysctl[0]['hosts'] == {
            'gw': 'changed'}
        assert all(t['handler'] for _r, t in ah.iter_tasks(runs, handler=True))


# ---------------------------------------------------------------------------
# inventory and configuration
# ---------------------------------------------------------------------------


class TestInventory:
    def test_live_inventory(self):
        inv = ah.parse_inventory_list(_live('final', 'ansible-inventory'))
        assert ah.group_hosts(inv, 'webservers') == {'web1', 'web2'}
        assert ah.group_hosts(inv, 'production') == {'web1', 'web2', 'lb'}
        assert ah.group_children(inv, 'production') == {'webservers', 'loadbalancers'}
        assert ah.group_hosts(inv, 'all') == {'web1', 'web2', 'lb', 'gw'}
        assert ah.hostvar(inv, 'web1', 'ansible_user') == 'ansible'
        assert ah.hostvar(inv, 'web1', 'ansible_host') == DATA['ips']['web1'].split('/')[0]
        assert ah.hostvar(inv, 'nope', 'ansible_host', 'x') == 'x'

    def test_untouched_inventory_is_empty(self):
        assert ah.parse_inventory_list(_live('untouched', 'ansible-inventory')) == {'groups': {}, 'hostvars': {}}

    def test_warning_before_json_and_garbage(self):
        inv = ah.parse_inventory_list('[WARNING]: x\n{"all": {"children": ["g"]}, "g": {"hosts": ["a"]}}')
        assert ah.group_hosts(inv, 'all') == {'a'}
        assert ah.parse_inventory_list('nothing') == {'groups': {}, 'hostvars': {}}
        assert ah.parse_inventory_list('{bad') == {'groups': {}, 'hostvars': {}}

    def test_children_cycle(self):
        inv = ah.parse_inventory_list('{"a": {"children": ["b"]}, "b": {"children": ["a"], "hosts": ["h"]}}')
        assert ah.group_hosts(inv, 'a') == {'h'}

    def test_live_config_dump(self):
        settings = ah.parse_config_dump(_live('final', 'ansible-config dump'))
        assert settings['DEFAULT_HOST_LIST'] == ('/root/ansible/ansible.cfg', ['/root/ansible/inventory.ini'])
        assert ah.config_value(settings, 'DEFAULT_VAULT_PASSWORD_FILE') == '/root/ansible/.vault_pass'
        assert ah.config_value(settings, 'HOST_KEY_CHECKING') is False
        assert ah.config_list(settings, 'DEFAULT_HOST_LIST') == ['/root/ansible/inventory.ini']
        assert ah.config_list(settings, 'MISSING') == [] and ah.config_value(settings, 'MISSING', 3) == 3
        # /root/ansible without ansible.cfg: only `CONFIG_FILE() = None`
        assert ah.parse_config_dump(_live('untouched', 'ansible-config dump')) == {'CONFIG_FILE': ('', None)}

    def test_config_dump_colours_and_raw_values(self):
        text = "\x1b[0;33mDEFAULT_HOST_LIST(env: ANSIBLE_INVENTORY) = a.ini,b.ini\x1b[0m\nnoise\n"
        settings = ah.parse_config_dump(text)
        assert settings['DEFAULT_HOST_LIST'][0] == 'env: ANSIBLE_INVENTORY'
        assert ah.config_list(settings, 'DEFAULT_HOST_LIST') == ['a.ini', 'b.ini']


# ---------------------------------------------------------------------------
# Vault, accounts, files
# ---------------------------------------------------------------------------


class TestVaultAndAccounts:
    def test_is_vault(self):
        assert ah.is_vault(_live('final', 'head -c 64'))
        assert ah.is_vault('$ANSIBLE_VAULT;1.2;AES256;dev\n3031')
        assert not ah.is_vault('---\nx: 1\n') and not ah.is_vault('') and not ah.is_vault(None)

    def test_crypt_check_cmd(self):
        cmd = ah.crypt_check_cmd('archiver', "p'a$s\"w`d")
        assert cmd.startswith('python3 -c "') and cmd.endswith('"')
        body = cmd[len('python3 -c "'):-1]
        assert '"' not in body and '$' not in body and '`' not in body
        assert base64.b64encode(b"p'a$s\"w`d").decode() in body and base64.b64encode(b'archiver').decode() in body
        assert 'libcrypt.so.1' in body

    def test_crypt_check_cmd_parses(self):
        """The code given to python3 -c is valid Python (it ran live: tests of the live fixture)."""
        code = ah.crypt_check_cmd('u', 'pw')[len('python3 -c "'):-1]
        compile(code, 'crypt_check', 'exec')

    def test_live_crypt(self):
        assert ah.crypt_matches(_live('final', 'libcrypt', 'web1'))
        assert not ah.crypt_matches(_live('untouched', 'libcrypt', 'web1'))
        assert _live('untouched', 'libcrypt', 'web1').strip() == ah.CRYPT_NOUSER
        assert not ah.crypt_matches('CRYPT=nomatch') and not ah.crypt_matches('')

    def test_users_groups_motd(self):
        passwd = _live('final', 'getent passwd', 'web1')
        users = ah.parse_users(passwd)
        names = [a['name'] for a in DATA['admins']]
        assert set(users) == set(names)
        assert all(users[a['name']]['uid'] == a['uid'] and users[a['name']]['shell'] == '/bin/bash'
                   for a in DATA['admins'])
        group = ah.parse_group_line(_live('final', 'getent group', 'web1'))
        assert group['name'] == 'ops' and group['gid'] == DATA['ops_gid'] and group['members'] == set(names)
        assert ah.parse_group_line('') is None and ah.parse_users('bad:line') == {}
        assert DATA['old_account'] in ah.parse_users(_live('untouched', 'getent passwd', 'web1'))
        motd = f"{DATA['company'].upper()}: managed by Ansible, do not edit by hand"
        assert ah.motd_matches(_live('final', '/etc/motd', 'web1'), motd)
        assert ah.motd_matches(motd + "  \n\n", motd) and not ah.motd_matches(motd + "\nmore", motd)
        assert not ah.motd_matches(_live('untouched', '/etc/motd', 'web1'), motd)


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


class _FakeScheme:
    def __init__(self):
        self.files, self.cmds = [], []

    def file(self, machine, filename, content, permissions=0o644, step=1, **kw):
        self.files.append((machine, filename, content, permissions, step))

    def cmd(self, machine, command, step=1, **kw):
        self.cmds.append((machine, command, step))


def test_install_trace():
    ns = _FakeScheme()
    ah.install_trace(ns, 'control', step=2)
    assert ns.files == [('control', ah.TRACE_PLUGIN_PATH, (_REPO / 'lib' / 'ansible_trace.py').read_text(), 0o644, 2)]
    assert ns.cmds == [('control', f"touch {ah.TRACE_LOG} && chmod 666 {ah.TRACE_LOG}", 2)]
    assert ah.read_trace_cmd(5) == f"tail -n 5 {ah.TRACE_LOG} 2>/dev/null; true"


def test_local_fact_json():
    text = ah.local_fact_json({'serial': 'SN-1', 'rack': 'A01'})
    assert json.loads(text) == {'serial': 'SN-1', 'rack': 'A01'} and text.endswith('\n')


# ---------------------------------------------------------------------------
# the callback plugin, through a stand-in ansible package
# ---------------------------------------------------------------------------


@pytest.fixture
def plugin(monkeypatch, tmp_path):
    ansible = types.ModuleType('ansible')
    ansible.__path__ = []
    plugins = types.ModuleType('ansible.plugins')
    plugins.__path__ = []
    callback = types.ModuleType('ansible.plugins.callback')

    class CallbackBase:
        def __init__(self, *args, **kwargs):
            pass

    callback.CallbackBase = CallbackBase
    playbook = types.ModuleType('ansible.playbook')
    playbook.__path__ = []
    handler_mod = types.ModuleType('ansible.playbook.handler')

    class Handler:
        pass

    handler_mod.Handler = Handler
    context = types.ModuleType('ansible.context')
    context.CLIARGS = {'check': True, 'subset': 'web*', 'tags': ('all',)}
    release = types.ModuleType('ansible.release')
    release.__version__ = '2.19.11'
    ansible.context = context
    for name, module in (('ansible', ansible), ('ansible.plugins', plugins), ('ansible.plugins.callback', callback),
                         ('ansible.playbook', playbook), ('ansible.playbook.handler', handler_mod),
                         ('ansible.context', context), ('ansible.release', release)):
        monkeypatch.setitem(sys.modules, name, module)
    spec = importlib.util.spec_from_file_location('sre_trace_under_test', _REPO / 'lib' / 'ansible_trace.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    log = tmp_path / 'runs.jsonl'
    monkeypatch.setattr(module, 'TRACE_LOG', str(log))
    module.Handler = Handler
    return module, Handler, log


class _Named:
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name


def _task(uuid, name, action, role=None, loop=None, run_once=False, delegate_to=None, cls=object):
    task = type('Task', (cls,), {})()
    task._uuid, task._role, task.loop, task.loop_with = uuid, role, loop, None
    task.resolved_action, task.action = action, action.rsplit('.', 1)[-1]
    task.run_once, task.delegate_to = run_once, delegate_to
    task.get_name = lambda: name
    return task


class _Result219:
    """2.19 CallbackTaskResult: public host / task (reading _host would warn)."""

    def __init__(self, host, task, changed=False):
        self.host, self.task, self._changed = _Named(host), task, changed

    def is_changed(self):
        return self._changed

    @property
    def _host(self):
        raise AssertionError("the plugin read the private attribute of a 2.19 result")


class _ResultOld:
    """An older TaskResult: private attributes only."""

    def __init__(self, host, task, changed=False):
        self._host, self._task, self._changed = _Named(host), task, changed

    def is_changed(self):
        return self._changed


class _Stats:
    processed = {'web1': 1, 'web2': 1}

    def summarize(self, host):
        return {'ok': 3, 'changed': 1 if host == 'web1' else 0, 'failures': 0, 'unreachable': 0, 'skipped': 0,
                'rescued': 0, 'ignored': 0}


@pytest.mark.parametrize('result_cls', [_Result219, _ResultOld])
def test_plugin_records_a_run(plugin, result_cls, tmp_path, monkeypatch):
    module, Handler, log = plugin
    monkeypatch.chdir(tmp_path)
    cb = module.CallbackModule()
    assert cb.CALLBACK_NEEDS_ENABLED is False and cb.CALLBACK_TYPE == 'aggregate'
    play = types.SimpleNamespace(hosts=['webservers'], serial=[1], get_name=lambda: 'Web servers')
    cb.v2_playbook_on_start(types.SimpleNamespace(_file_name='web.yml'))
    cb.v2_playbook_on_play_start(play)
    role = _Named('webserver')
    t1 = _task('u1', 'webserver : Site configuration', 'ansible.builtin.template', role=role)
    t2 = _task('u2', 'Users', 'ansible.builtin.user', loop=['a', 'b'])
    t3 = _task('u3', 'Report', 'ansible.builtin.template', run_once=True, delegate_to='localhost')
    h1 = _task('u4', 'webserver : Reload nginx', 'ansible.builtin.systemd_service', role=role, cls=Handler)
    cb.v2_playbook_on_task_start(t1, False)
    cb.v2_runner_on_ok(result_cls('web1', t1, changed=True))
    cb.v2_runner_on_ok(result_cls('web2', t1))
    cb.v2_playbook_on_task_start(t2, False)
    cb.v2_runner_on_failed(result_cls('web1', t2))
    cb.v2_runner_on_failed(result_cls('web2', t2), ignore_errors=True)
    cb.v2_playbook_on_task_start(t3, False)
    cb.v2_runner_on_skipped(result_cls('web1', t3))
    cb.v2_runner_on_unreachable(result_cls('web2', t3))
    cb.v2_playbook_on_handler_task_start(h1)
    cb.v2_runner_on_ok(result_cls('web1', h1, changed=True))
    cb.v2_runner_on_ok(object())                      # a broken result is ignored
    cb.v2_playbook_on_stats(_Stats())
    runs = ah.parse_runs(log.read_text())
    assert len(runs) == 1
    run = runs[0]
    assert run['playbook'] == str(tmp_path / 'web.yml') and run['cwd'] == str(tmp_path)
    assert run['check'] is True and run['limit'] == 'web*' and run['ansible'] == '2.19.11'
    assert run['plays'] == [{'name': 'Web servers', 'hosts': 'webservers', 'serial': ['1']}]
    tasks = {t['name']: t for t in run['tasks']}
    assert tasks['webserver : Site configuration'] == {
        'play': 0, 'name': 'webserver : Site configuration', 'action': 'ansible.builtin.template',
        'role': 'webserver', 'handler': False, 'loop': False, 'run_once': False, 'delegate_to': '',
        'hosts': {'web1': 'changed', 'web2': 'ok'}}
    assert tasks['Users']['loop'] is True and tasks['Users']['hosts'] == {'web1': 'failed', 'web2': 'ignored'}
    assert tasks['Report']['run_once'] and tasks['Report']['delegate_to'] == 'localhost'
    assert tasks['Report']['hosts'] == {'web1': 'skipped', 'web2': 'unreachable'}
    assert tasks['webserver : Reload nginx']['handler'] is True
    assert run['recap']['web1']['changed'] == 1 and run['recap']['web2']['changed'] == 0
    assert 'args' not in json.dumps(run)


def test_plugin_never_raises(plugin, monkeypatch):
    module, _Handler, log = plugin
    cb = module.CallbackModule()
    monkeypatch.setattr(module, 'TRACE_LOG', '/nonexistent-dir/runs.jsonl')
    cb.v2_playbook_on_start(None)
    cb.v2_playbook_on_play_start(None)
    cb.v2_playbook_on_task_start(None, False)
    cb.v2_runner_on_ok(None)
    cb.v2_playbook_on_stats(None)
    cb.v2_playbook_on_stats(_Stats())                 # unwritable log: nothing raised
