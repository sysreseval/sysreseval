"""``sre status``: what runs on this machine (privileged only, read-only).

Prints the version of SRE, whether the web agent (``sre-agent``) runs, and every running project
with its origin, the user who created it and its container engine::

    sre 0.17.0
    sre-agent: running (pid 812)
    local drain: allowed, not asked
    running projects: 2
    ORIGIN  USER   ENGINE   PROJECT
    web     alice  podman   20261118091203@@@sre@dhcp.py@@@alice
    local   bob    kathara  20261118091540@@@sre@nftables-filter1.py@@@bob

The origin and the user come from the origin file of each project (``origin.py``, written by
``sre start``); a project created before that file existed shows ``?`` and the user of its name.
The engine is the one that file records, else the default engine of the host (what every
command asks for such a project: ``engine_name_of_project()``).
The projects are those of ``sre stop-all`` run by a privileged caller: the directories holding an
``info.json``, in start order.

The ``local drain:`` line is there on a pool host whose agent knows the drains asked on the host
itself (``sre set-drain``, ``local_drain.py``): ``forbidden``, ``allowed, not asked`` or ``allowed,
asked on 2026-11-19 at 17:02:10``.

With ``--json`` the same information is printed as one JSON document (:func:`status_dict`), for
scripts::

    {"sre_version": "0.17.0",
     "agent": {"running": true, "pids": [812], "configured": true, "config_file": "/etc/sreweb/agent.toml",
               "local_drain": {"allowed": true, "asked": false, "asked_at": null}},
     "projects": [{"running_lab_name": "20261118091203@@@sre@dhcp.py@@@alice", "lab_name": "sre@dhcp.py",
                   "origin": "web", "user": "alice", "engine": "podman"}]}

``running`` and ``pids`` are ``null`` without ``/proc``; ``local_drain`` is ``null`` when the agent
of the host says nothing about it (no agent, an older one), ``asked_at`` is in epoch seconds;
``origin`` is ``null`` where the table shows ``?`` (and ``engine`` when the engine parameters of
``params.py`` name no engine).

The agent has neither a pid file nor a local socket, and its unit name depends on the layout:
it is looked for in ``/proc`` (:func:`agent_pids`, on the scan of ``procscan.py``).
"""
import json
import os
import time

from .. import local_drain, params
from ..engine import EngineError, engine_name_of_project
from ..origin import read_origin
from ..procscan import command_lines, runs_script
from ..utils import user_not_allowed
from .stop_all import accessible_projects

#: How the agent appears in a command line: the script both launchers exec, or the module.
AGENT_SCRIPT = 'sre_agent.py'
AGENT_MODULE = 'sreweb.agent'

UNKNOWN_ORIGIN = '?'
_COLUMNS = ('ORIGIN', 'USER', 'ENGINE', 'PROJECT')


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


def _engine_of(running_lab_name: str) -> str:
    try:
        return engine_name_of_project(running_lab_name)
    except EngineError:     # no record, and the parameters of the host name no engine
        return UNKNOWN_ORIGIN


def project_rows() -> list[tuple[str, str, str, str]]:
    """``(origin, user, engine, running_lab_name)`` of every running project, in start order."""
    rows = []
    for running_lab_name, _lab_hash in accessible_projects():
        origin = read_origin(params.origin_filename(running_lab_name))
        engine = _engine_of(running_lab_name)
        if origin is None:
            rows.append((UNKNOWN_ORIGIN, params.get_username_from_running_lab_name(running_lab_name), engine,
                         running_lab_name))
        else:
            rows.append((origin[params.origin_keyword], origin[params.origin_user_keyword], engine,
                         running_lab_name))
    return rows


def local_drain_line(drain: dict) -> str:
    """The ``local drain:`` line for the *drain* of ``local_drain.summary()``."""
    if not drain[params.local_drain_allowed_keyword]:
        state = "forbidden"
    elif not drain[params.local_drain_asked_keyword]:
        state = "allowed, not asked"
    else:
        asked_at = time.localtime(drain[params.local_drain_asked_at_keyword])
        state = f"allowed, asked on {time.strftime('%Y-%m-%d', asked_at)} at {time.strftime('%H:%M:%S', asked_at)}"
    return f"local drain: {state}"


def status_lines(pids: list[int] | None, configured: bool, rows: list[tuple[str, str, str, str]],
                 drain: dict | None = None) -> list[str]:
    """*drain*: ``local_drain.summary()``, ``None`` when the agent of the host says nothing about
    the local drains (no line then)."""
    lines = [f"sre {params.sre_version}", agent_line(pids, configured),
             *([local_drain_line(drain)] if drain is not None else []),
             f"running projects: {len(rows) if rows else 'none'}"]
    if rows:
        table = [_COLUMNS, *rows]
        widths = [max(len(row[i]) for row in table) for i in range(len(_COLUMNS) - 1)]
        lines += ['  '.join([*(cell.ljust(width) for cell, width in zip(row, widths)), row[-1]]) for row in table]
    return lines


def status_dict(pids: list[int] | None, configured: bool, rows: list[tuple[str, str, str, str]],
                drain: dict | None = None) -> dict:
    """The document of ``sre status --json``: the inputs of :func:`status_lines`, without the
    display placeholders (``None`` for an unknown origin, without ``/proc``, or for the local
    drain of a host whose agent says nothing about it)."""
    return {
        params.status_sre_version_keyword: params.sre_version,
        params.status_agent_keyword: {
            params.status_agent_running_keyword: None if pids is None else bool(pids),
            params.status_agent_pids_keyword: pids,
            params.status_agent_configured_keyword: configured,
            params.status_agent_config_file_keyword: params.agent_config_file,
            params.local_drain_keyword: drain,
        },
        params.status_projects_keyword: [{
            params.running_lab_name_keyword: running_lab_name,
            params.status_lab_name_keyword: params.get_lab_name_from_running_lab_name(running_lab_name),
            params.origin_keyword: None if origin == UNKNOWN_ORIGIN else origin,
            params.origin_user_keyword: user,
            params.origin_engine_keyword: None if engine == UNKNOWN_ORIGIN else engine,
        } for origin, user, engine, running_lab_name in rows],
    }


def action_status(as_json: bool = False):
    user_not_allowed()
    pids, configured, rows = agent_pids(), os.path.exists(params.agent_config_file), project_rows()
    drain = local_drain.summary()
    if as_json:
        print(json.dumps(status_dict(pids, configured, rows, drain), ensure_ascii=False))
    else:
        print('\n'.join(status_lines(pids, configured, rows, drain)))
