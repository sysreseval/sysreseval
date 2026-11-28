"""The container engines of SRE: what deploys the machines of a project and acts on them.

``get_engine(name)`` gives the engine of that name, one object per name and process; ``base``
says what an engine provides.  Two engines: Kathara over Docker (``kathara_engine``) and
rootless Podman (``podman_engine``).

A project is run by one engine, chosen when it is created (``choice``) among those the host
allows (``params.host_allowed_engines()``, the default one first) and recorded in the project
(``origin``); every later command asks :func:`engine_of_project`.  Without a name,
``get_engine()`` gives the default engine of the host (``params.container_engine`` and, host
by host, ``params.container_engine_by_host``).
"""
import os
import threading

from .. import params
from .base import Engine, EngineError, SwitchModesUnsupported  # noqa: F401 (the names callers use)

_engines: dict = {}
_engines_lock = threading.Lock()


def _new_engine(name: str) -> Engine:
    """The engine *name*.  Its module is imported here, not with this package: a host needs the
    software of its own engines only."""
    if name == params.container_engine_podman:
        from .podman_engine import PodmanEngine
        return PodmanEngine()
    if name != params.container_engine_kathara:
        raise EngineError(f"{name!r} is not a container engine ({', '.join(params.container_engines)})")
    try:
        from .kathara_engine import KatharaEngine
    except ImportError as e:    # a host installed for the other engine: neither Kathara nor the Docker SDK
        raise EngineError(f"the Kathara engine is asked for on this host (container_engine and "
                          f"container_engines_allowed of params.py) and it is not installed ({e}): "
                          f"{params.kathara_missing_hint}") from None
    return KatharaEngine()


def get_engine(name: str | None = None) -> Engine:
    """The engine *name* of this process, created at the first call (evaluations run in
    threads); without a name, the default engine of this host."""
    if name is None:
        try:
            name = params.host_container_engine()
        except ValueError as e:
            raise EngineError(str(e)) from None
    engine = _engines.get(name)
    if engine is None:
        with _engines_lock:
            engine = _engines.get(name)
            if engine is None:
                engine = _engines[name] = _new_engine(name)
    return engine


def allowed_engine_names() -> tuple:
    """The names of the engines this host allows, its default first; an `EngineError` when the
    parameters do not say so properly."""
    try:
        return params.host_allowed_engines()
    except ValueError as e:
        raise EngineError(str(e)) from None


def engine_name_of_project(running_lab_name: str) -> str:
    """The name of the engine of the running project *running_lab_name*: the one its origin
    file records, else the default engine of this host (a project created before the engine
    was recorded, when a host had one engine)."""
    from ..origin import recorded_engine    # the two engine modules import nothing of SRE but params

    name = recorded_engine(params.origin_filename(running_lab_name))
    if name is None:
        try:
            name = params.host_container_engine()
        except ValueError as e:
            raise EngineError(str(e)) from None
    return name


def engine_of_project(running_lab_name: str) -> Engine:
    """The engine of the running project *running_lab_name* (:func:`engine_name_of_project`).
    The host need not allow it any more: a project is always evaluated and stopped by the
    engine that runs it."""
    return get_engine(engine_name_of_project(running_lab_name))


def engine_names_in_use() -> tuple:
    """The engines a host-wide command must go over: those the host allows, its default first,
    then those recorded by the projects still there (an engine the host allowed when they were
    started)."""
    from ..origin import recorded_engine

    names = list(allowed_engine_names())
    try:
        projects = sorted(os.listdir(params.sre_projects_dir))
    except OSError:
        projects = []
    for running_lab_name in projects:
        name = recorded_engine(params.origin_filename(running_lab_name))
        if name is not None and name not in names:
            names.append(name)
    return tuple(names)
