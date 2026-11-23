# Copyright: SysResEval
"""sre_trace: the Ansible callback plugin of the Ansible lab (lab/sre/_DRAFT_misc/ansible.py).

Never imported by SRE: ``ansible_helpers.install_trace()`` copies this file to the control node as
``/usr/share/ansible/plugins/callback/sre_trace.py``, one of the default callback paths.  A callback
that does not need to be enabled (``CALLBACK_NEEDS_ENABLED = False``) is loaded by every
``ansible-playbook`` run whatever the ``ansible.cfg`` of the students (an ad hoc ``ansible``
command loads no extra callback unless ``bin_ansible_callbacks`` is set).

It prints nothing.  When a run ends (``v2_playbook_on_stats``) it appends one JSON line to
``/var/log/ansible-runs.jsonl``: the time, the playbook, the working directory, the check mode, the
plays, the tasks (name, module, role, handler, loop, run_once, delegate_to and the status of each
host: ok / changed / failed / ignored / skipped / unreachable) and the recap.  The arguments of the
tasks are never recorded (a password set from a vault would land in the file).  Every hook swallows
its exceptions: a fault of the trace must never break the students' run.
"""
from __future__ import annotations

DOCUMENTATION = '''
    name: sre_trace
    type: aggregate
    short_description: records each ansible-playbook run for the evaluation of the SRE Ansible lab
    description:
      - Appends one JSON line per run to /var/log/ansible-runs.jsonl (no task argument is recorded).
    requirements: []
'''

import json
import os
import time

from ansible.plugins.callback import CallbackBase

try:
    from ansible.playbook.handler import Handler
except Exception:                                   # pragma: no cover - very old Ansible
    Handler = None

TRACE_LOG = '/var/log/ansible-runs.jsonl'


def _attr(obj, public, private):
    """``obj.public`` (Ansible >= 2.19, ``CallbackTaskResult``), else ``obj.private`` (older
    ``TaskResult``): reading the private name on 2.19 would print a deprecation warning."""
    try:
        return getattr(obj, public)
    except AttributeError:
        return getattr(obj, private, None)


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'sre_trace'
    CALLBACK_NEEDS_ENABLED = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._run = {'start': time.time(), 'playbook': '', 'cwd': '', 'check': False, 'plays': [], 'tasks': []}
        self._tasks = {}              # uuid -> task record
        self._play = -1
        try:
            self._run['cwd'] = os.getcwd()
            from ansible import context
            self._run['check'] = bool(context.CLIARGS.get('check', False))
            self._run['limit'] = context.CLIARGS.get('subset') or ''
            self._run['tags'] = list(context.CLIARGS.get('tags') or ())
        except Exception:
            pass
        try:
            from ansible.release import __version__
            self._run['ansible'] = __version__
        except Exception:
            pass

    # -- playbook / play / task ------------------------------------------------------------------

    def v2_playbook_on_start(self, playbook):
        try:
            name = getattr(playbook, '_file_name', '') or ''
            self._run['playbook'] = os.path.abspath(name) if name else ''
        except Exception:
            pass

    def v2_playbook_on_play_start(self, play):
        try:
            hosts = play.hosts
            if isinstance(hosts, (list, tuple)):
                hosts = ','.join(str(h) for h in hosts)
            self._run['plays'].append({'name': str(play.get_name() or ''), 'hosts': str(hosts or ''),
                                       'serial': [str(s) for s in (getattr(play, 'serial', None) or [])]})
            self._play = len(self._run['plays']) - 1
        except Exception:
            pass

    def _task(self, task, handler=False):
        try:
            uuid = task._uuid
            if uuid in self._tasks:
                return self._tasks[uuid]
            role = getattr(task, '_role', None)
            action = getattr(task, 'resolved_action', None) or getattr(task, 'action', '') or ''
            record = {
                'play': self._play,
                'name': str(task.get_name() or ''),
                'action': str(action),
                'role': str(role.get_name()) if role is not None else '',
                'handler': bool(handler or (Handler is not None and isinstance(task, Handler))),
                'loop': bool(getattr(task, 'loop', None) is not None or getattr(task, 'loop_with', None)),
                'run_once': bool(getattr(task, 'run_once', False)),
                'delegate_to': str(getattr(task, 'delegate_to', None) or ''),
                'hosts': {},
            }
            self._tasks[uuid] = record
            self._run['tasks'].append(record)
            return record
        except Exception:
            return None

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._task(task)

    def v2_playbook_on_handler_task_start(self, task):
        self._task(task, handler=True)

    # -- results ---------------------------------------------------------------------------------

    def _result(self, result, status):
        try:
            task = _attr(result, 'task', '_task')
            host = _attr(result, 'host', '_host')
            record = self._task(task)
            if record is None or host is None:
                return
            if status == 'ok':
                try:
                    if result.is_changed():
                        status = 'changed'
                except Exception:
                    pass
            record['hosts'][str(host.get_name())] = status
        except Exception:
            pass

    def v2_runner_on_ok(self, result):
        self._result(result, 'ok')

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._result(result, 'ignored' if ignore_errors else 'failed')

    def v2_runner_on_skipped(self, result):
        self._result(result, 'skipped')

    def v2_runner_on_unreachable(self, result):
        self._result(result, 'unreachable')

    # -- the end of the run ----------------------------------------------------------------------

    def v2_playbook_on_stats(self, stats):
        try:
            recap = {}
            for host in sorted(stats.processed.keys()):
                recap[str(host)] = {k: int(v) for k, v in stats.summarize(host).items()}
            self._run['recap'] = recap
            self._run['end'] = time.time()
            line = json.dumps(self._run, sort_keys=True, separators=(',', ':')) + '\n'
            with open(TRACE_LOG, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass
