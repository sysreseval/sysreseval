"""Simple in-memory rate limits of the portal: at most one action per interval for a key (the
login or the client address)."""
import time


class RateLimiter:
    def __init__(self):
        self._last: dict[tuple, float] = {}
        self._counts: dict[tuple, list] = {}

    def allow_every(self, kind: str, key: str, interval: float, now: float | None = None) -> float:
        """0 when the action is allowed now (and recorded), else the seconds to wait."""
        now = time.monotonic() if now is None else now
        last = self._last.get((kind, key))
        if last is not None and now - last < interval:
            return interval - (now - last)
        self._last[(kind, key)] = now
        return 0.0

    def allow_per_minute(self, kind: str, key: str, limit: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        stamps = [t for t in self._counts.get((kind, key), []) if now - t < 60]
        if len(stamps) >= limit:
            self._counts[(kind, key)] = stamps
            return False
        stamps.append(now)
        self._counts[(kind, key)] = stamps
        return True
