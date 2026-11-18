"""The origin file of a running project: ``.private/origin.json``.

Written once, when the project is created (``start.create_project_directories``: ``sre start``,
``sre restore``, ``sre pre-start-exam``), and read by ``sre status``.  It tells where the project
was started from and by whom::

    {"origin": "web", "user": "alice"}

* ``params.origin_keyword``: ``params.origin_local`` (the Qt GUI through ``sre-wrapper``, or
  ``sre`` run by root) or ``params.origin_web`` (the web agent, for a browser user);
* ``params.origin_user_keyword``: the user who created the project (``SRE.username``: the Unix
  login of a local project, the portal login of a web one).

The web agent names itself through the environment it builds for every ``sre`` it runs
(``params.sre_origin_env_variable``).  The variable is only trusted when sudo did not launch
``sre``: in the student path (``sre-wrapper`` → sudo) the environment is the student's.

Nothing here reads the real process state: every function takes plain values (see
``tests/test_origin.py``).
"""
import json
import os

from . import params

_ORIGINS = (params.origin_local, params.origin_web)


def project_origin(env, *, by_sudo: bool) -> str:
    """The origin of a project created by a ``sre`` whose environment is *env*: web when the
    caller says so and was not launched by sudo (*by_sudo*: ``access.launched_by_sudo()``),
    local otherwise."""
    if not by_sudo and env.get(params.sre_origin_env_variable) == params.origin_web:
        return params.origin_web
    return params.origin_local


def write_origin(path, origin: str, user: str) -> None:
    """Create the origin file *path* (mode 0600); it must not exist yet."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump({params.origin_keyword: origin, params.origin_user_keyword: user}, f)


def read_origin(path) -> dict | None:
    """The content of the origin file *path*: ``{origin, user}``, or ``None`` when the file is
    missing (a project created before the file existed), unreadable, or not what
    :func:`write_origin` writes."""
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    origin, user = data.get(params.origin_keyword), data.get(params.origin_user_keyword)
    if origin not in _ORIGINS or not isinstance(user, str):
        return None
    return {params.origin_keyword: origin, params.origin_user_keyword: user}
