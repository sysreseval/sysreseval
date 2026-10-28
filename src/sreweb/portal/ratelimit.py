"""Simple in-memory rate limits of the portal: at most one action per interval for a key (the
login or the client address)."""
import time


class RateLimiter:
    def __init__(self):
        self._last: dict[tuple, float] = {}
        self._counts: dict[tuple, list] = {}

    def take_every(self, kind: str, key: str, interval: float, now: float | None = None) -> tuple[float, float | None]:
        """Take the slot of *key*: ``(0, previous)`` when the action is allowed now and recorded
        (*previous* is the timestamp replaced, None when the key had none: what ``give_back()``
        takes), else ``(seconds to wait, None)``."""
        now = time.monotonic() if now is None else now
        last = self._last.get((kind, key))
        if last is not None and now - last < interval:
            return interval - (now - last), None
        self._last[(kind, key)] = now
        return 0.0, last

    def allow_every(self, kind: str, key: str, interval: float, now: float | None = None) -> float:
        """0 when the action is allowed now (and recorded), else the seconds to wait."""
        return self.take_every(kind, key, interval, now)[0]

    def give_back(self, kind: str, key: str, previous: float | None) -> None:
        """Undo a ``take_every()`` that allowed the action: the slot was taken for nothing (a
        start that created no project).  Valid right after the take, by the same request: the
        requests of the same key made meanwhile were refused, so the entry is still the one taken."""
        if previous is None:
            self._last.pop((kind, key), None)
        else:
            self._last[(kind, key)] = previous

    def allow_per_minute(self, kind: str, key: str, limit: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        stamps = [t for t in self._counts.get((kind, key), []) if now - t < 60]
        if len(stamps) >= limit:
            self._counts[(kind, key)] = stamps
            return False
        stamps.append(now)
        self._counts[(kind, key)] = stamps
        return True
