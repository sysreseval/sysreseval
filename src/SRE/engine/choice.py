"""Which engine runs a new project.

A host allows some engines, its default one first (``params.host_allowed_engines()``); a lab
may accept only some (its ``container_engines`` attribute); a privileged caller may ask for
one (``sre start --engine``).  :func:`choose_engine` gives the engine of the project, or says
why there is none.

Nothing here loads an engine nor reads the state of the host: the functions take plain values
(see ``tests/test_engine_choice.py``).
"""
from .. import params


class EngineChoiceError(Exception):
    """No engine can run the project.  The message names the engines: it is for a privileged
    caller (a student is only told that the lab cannot be started on the host)."""


def _names(engines) -> str:
    return ', '.join(engines)


def lab_engines(module) -> tuple | None:
    """The engines the lab *module* accepts: its ``container_engines`` attribute
    (``params.lab_engines_attribute``), in its order and without repetition; ``None`` when the
    lab says nothing (it accepts every engine).  ValueError when the attribute is not a list of
    engines with at least one name."""
    value = getattr(module, params.lab_engines_attribute, None)
    if value is None:
        return None
    attribute = params.lab_engines_attribute
    if isinstance(value, str) or not isinstance(value, (tuple, list)) or not value:
        raise ValueError(f"{attribute} = {value!r}: a list of container engines is expected "
                         f"({_names(params.container_engines)})")
    for engine in value:
        if engine not in params.container_engines:
            raise ValueError(f"{attribute} = {value!r}: {engine!r} is not a container engine "
                             f"({_names(params.container_engines)})")
    return tuple(dict.fromkeys(value))


def choose_engine(requested: str | None, host_allowed, lab_accepted=None) -> str:
    """The engine of a new project.

    *host_allowed*: the engines of the host, its default first.  *lab_accepted*: the engines
    of the lab, ``None`` for all.  *requested*: the engine a privileged caller asks for, which
    the host must allow and the lab accept; without one, the first engine of the host that the
    lab accepts.  :class:`EngineChoiceError` when there is none."""
    if requested is not None:
        if requested not in params.container_engines:
            raise EngineChoiceError(f"{requested!r} is not a container engine ({_names(params.container_engines)})")
        if requested not in host_allowed:
            raise EngineChoiceError(f"this host does not allow the engine {requested} "
                                    f"(it allows: {_names(host_allowed)})")
        if lab_accepted is not None and requested not in lab_accepted:
            raise EngineChoiceError(f"this lab does not accept the engine {requested} "
                                    f"(it accepts: {_names(lab_accepted)})")
        return requested
    for engine in host_allowed:
        if lab_accepted is None or engine in lab_accepted:
            return engine
    raise EngineChoiceError(f"this lab accepts only {_names(lab_accepted)}; "
                            f"this host allows only {_names(host_allowed)}")
