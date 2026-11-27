"""The container engine of SRE: what deploys the machines of a project and acts on them.

``get_engine()`` gives the engine of this process; ``base`` says what an engine provides.
There is one engine today, Kathara over Docker (``kathara_engine``).
"""
import threading

from .base import Engine, SwitchModesUnsupported  # noqa: F401 (the names callers use)
from .kathara_engine import KatharaEngine

_engine = None
_engine_lock = threading.Lock()


def get_engine() -> Engine:
    """The engine of this process, created at the first call (evaluations run in threads)."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = KatharaEngine()
    return _engine
