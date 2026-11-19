"""``sre status``: what runs on this machine (privileged only, read-only).

Prints the version of SRE, whether the web agent (``sre-agent``) runs, and every running project
with its origin and the user who created it::

    sre 0.17.0
    sre-agent: running (pid 812)
    running projects: 2
    ORIGIN  USER   PROJECT
    web     alice  20261118091203@@@sre@dhcp.py@@@alice
    local   bob    20261118091540@@@sre@nftables-filter1.py@@@bob

The origin and the user come from the origin file of each project (``origin.py``, written by
``sre start``); a project created before that file existed shows ``?`` and the user of its name.
The projects are those of ``sre stop-all`` run by a privileged caller: the directories holding an
``info.json``, in start order.

With ``--json`` the same information is printed as one JSON document (:func:`status_dict`), for
scripts::

    {"sre_version": "0.17.0",
     "agent": {"running": true, "pids": [812], "configured": true, "config_file": "/etc/sreweb/agent.toml"},
     "projects": [{"running_lab_name": "20261118091203@@@sre@dhcp.py@@@alice", "lab_name": "sre@dhcp.py",
                   "origin": "web", "user": "alice"}]}

``running`` and ``pids`` are ``null`` without ``/proc``; ``origin`` is ``null`` where the table shows ``?``.

The agent has neither a pid file nor a local socket, and its unit name depends on the layout:
it is looked for in ``/proc`` (:func:`agent_pids`, on the scan of ``procscan.py``).
"""
import json
import os

from .. import params
from ..origin import read_origin
from ..procscan import command_lines, runs_script
from ..utils import user_not_allowed
from .stop_all import accessible_projects

#: How the agent appears in a command line: the script both launchers exec, or the module.
AGENT_SCRIPT = 'sre_agent.py'
AGENT_MODULE = 'sreweb.agent'

UNKNOWN_ORIGIN = '?'
_COLUMNS = ('ORIGIN', 'USER', 'PROJECT')


def _is_agent(argv: list[str]) -> bool:
    """A Python interpreter running the agent's script or module: not the shell wrapper that
    execs it, nor an editor or a grep naming the file."""
    return runs_script(argv, AGENT_SCRIPT, AGENT_MODULE)


def agent_pids(proc: str = '/proc') -> list[int] | None:
    """The pids of the running web agents (normally one), sorted; ``None`` when *proc* cannot
    be listed (not a Linux system).  A process that ended meanwhile or cannot be read is skipped."""
    lines = command_lines(proc)
    if lines is None:
        return None
    return sorted(pid for pid, argv in lines if _is_agent(argv))


def agent_line(pids: list[int] | None, configured: bool) -> str:
    """The ``sre-agent:`` line for the *pids* of :func:`agent_pids`; *configured*: the agent's
    configuration file exists (without it the host is not a pool host)."""
    if pids is None:
        state = "unknown (no /proc)"
    elif pids:
        state = f"running ({'pid' if len(pids) == 1 else 'pids'} {', '.join(str(pid) for pid in pids)})"
    elif configured:
        state = "not running"
    else:
        state = f"not running (no {params.agent_config_file})"
    return f"sre-agent: {state}"


def project_rows() -> list[tuple[str, str, str]]:
    """``(origin, user, running_lab_name)`` of every running project, in start order."""
    rows = []
    for running_lab_name, _lab_hash in accessible_projects():
        origin = read_origin(params.origin_filename(running_lab_name))
        if origin is None:
            rows.append((UNKNOWN_ORIGIN, params.get_username_from_running_lab_name(running_lab_name),
                         running_lab_name))
        else:
            rows.append((origin[params.origin_keyword], origin[params.origin_user_keyword], running_lab_name))
    return rows


def status_lines(pids: list[int] | None, configured: bool, rows: list[tuple[str, str, str]]) -> list[str]:
    lines = [f"sre {params.sre_version}", agent_line(pids, configured),
             f"running projects: {len(rows) if rows else 'none'}"]
    if rows:
        table = [_COLUMNS, *rows]
        widths = [max(len(row[i]) for row in table) for i in range(len(_COLUMNS) - 1)]
        lines += ['  '.join([*(cell.ljust(width) for cell, width in zip(row, widths)), row[-1]]) for row in table]
    return lines


def status_dict(pids: list[int] | None, configured: bool, rows: list[tuple[str, str, str]]) -> dict:
    """The document of ``sre status --json``: the inputs of :func:`status_lines`, without the
    display placeholders (``None`` for an unknown origin or without ``/proc``)."""
    return {
        params.status_sre_version_keyword: params.sre_version,
        params.status_agent_keyword: {
            params.status_agent_running_keyword: None if pids is None else bool(pids),
            params.status_agent_pids_keyword: pids,
            params.status_agent_configured_keyword: configured,
            params.status_agent_config_file_keyword: params.agent_config_file,
        },
        params.status_projects_keyword: [{
            params.running_lab_name_keyword: running_lab_name,
            params.status_lab_name_keyword: params.get_lab_name_from_running_lab_name(running_lab_name),
            params.origin_keyword: None if origin == UNKNOWN_ORIGIN else origin,
            params.origin_user_keyword: user,
        } for origin, user, running_lab_name in rows],
    }


def action_status(as_json: bool = False):
    user_not_allowed()
    pids, configured, rows = agent_pids(), os.path.exists(params.agent_config_file), project_rows()
    if as_json:
        print(json.dumps(status_dict(pids, configured, rows), ensure_ascii=False))
    else:
        print('\n'.join(status_lines(pids, configured, rows)))
