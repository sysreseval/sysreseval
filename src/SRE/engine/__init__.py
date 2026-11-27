"""The container engine of SRE: what deploys the machines of a project and acts on them.

``get_engine()`` gives the engine of this process; ``base`` says what an engine provides.
Two engines: Kathara over Docker (``kathara_engine``) and rootless Podman (``podman_engine``).
The site chooses with ``params.container_engine`` and, host by host, with
``params.container_engine_by_host``.
"""
import threading

from .. import params
from .base import Engine, EngineError, SwitchModesUnsupported  # noqa: F401 (the names callers use)

_engine = None
_engine_lock = threading.Lock()


def _new_engine() -> Engine:
    """The engine `params` names for this host.  Its module is imported here, not with this
    package: a host needs the software of its own engine only."""
    try:
        name = params.host_container_engine()
    except ValueError as e:
        raise EngineError(str(e)) from None
    if name == params.container_engine_podman:
        from .podman_engine import PodmanEngine
        return PodmanEngine()
    from .kathara_engine import KatharaEngine
    return KatharaEngine()


def get_engine() -> Engine:
    """The engine of this process, created at the first call (evaluations run in threads)."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = _new_engine()
    return _engine
