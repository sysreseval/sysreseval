"""The last evaluation of each project of the host, read from the archives of
``params.archive_dirs`` (``SRE.archive_summary``): what the Watch page of the instructors shows
and what the Evaluation tab of an instructor opens on.

On demand only: a refresh scans the directories once (one ``scandir`` per directory, the newest
archive per running lab name by its 14-digit prefix) and parses the newest archive of the
projects asked for, in a thread; the scan is kept for ``ttl`` seconds (the Watch page polls every
5 s).  Nothing is read while nobody watches.  A new evaluation is a new file, so a path is the
key of its summary; ``invalidate()`` forces the next refresh (after an evaluation the agent ran).
"""
import asyncio
import logging
import time

from SRE import params
from SRE.archive_summary import (ArchiveSummary, newest_by_running_lab_name, read_archive, scan_archive_dirs,
                                 summarize)

log = logging.getLogger('sreweb.agent')


class ArchiveIndex:
    def __init__(self, dirs=None, *, ttl: float = 5.0):
        """*dirs*: the archive directories (``params.archive_dirs`` when ``None``)."""
        self.dirs = list(dirs) if dirs is not None else None
        self.ttl = ttl
        self._newest: dict[str, str] = {}          # running lab name -> path of its newest archive
        self._summaries: dict[str, ArchiveSummary] = {}
        self._raw: dict[str, dict] = {}            # the archives read in full (the Evaluation tab)
        self._scanned_at: float | None = None
        self._lock = asyncio.Lock()
        self.scans = 0

    def _dirs(self) -> list:
        return self.dirs if self.dirs is not None else list(params.archive_dirs)

    def _fresh(self) -> bool:
        return self._scanned_at is not None and time.monotonic() - self._scanned_at < self.ttl

    def invalidate(self):
        self._scanned_at = None

    async def refresh(self, rlns=None, *, force: bool = False):
        """Scan the directories unless the last scan is younger than *ttl* (or *force*), and
        summarise the newest archive of the projects of *rlns* (every one when ``None``)."""
        if self._fresh() and not force:
            return
        async with self._lock:
            if self._fresh() and not force:
                return
            newest = await asyncio.to_thread(self._scan)
            wanted = set(rlns) if rlns is not None else set(newest)
            todo = [newest[r] for r in wanted if r in newest and newest[r] not in self._summaries]
            if todo:
                self._summaries.update(await asyncio.to_thread(self._summarize, todo))
            keep = set(newest.values())
            self._summaries = {p: s for p, s in self._summaries.items() if p in keep}
            self._raw = {p: r for p, r in self._raw.items() if p in keep}
            self._newest = newest
            self._scanned_at = time.monotonic()
            self.scans += 1

    def _scan(self) -> dict:
        return newest_by_running_lab_name(scan_archive_dirs(self._dirs()))

    @staticmethod
    def _summarize(paths) -> dict:
        result = {}
        for path in paths:
            try:
                result[path] = summarize(read_archive(path), path)
            except Exception as e:   # a truncated or foreign file must not hide the others
                log.warning("cannot read the archive %s: %s", path, e)
        return result

    def summary(self, rln: str) -> ArchiveSummary | None:
        """The summary of the newest archive of *rln* known to the last refresh."""
        path = self._newest.get(rln)
        return self._summaries.get(path) if path else None

    async def archive(self, rln: str) -> tuple | None:
        """``(summary, archive dict)`` of the newest archive of *rln* (refreshing first), or
        ``None``."""
        await self.refresh({rln})
        path = self._newest.get(rln)
        if not path:
            return None
        if path not in self._raw:
            try:
                self._raw[path] = await asyncio.to_thread(read_archive, path)
            except Exception as e:
                log.warning("cannot read the archive %s: %s", path, e)
                return None
        raw = self._raw[path]
        summary = self._summaries.get(path)
        if summary is None:
            summary = self._summaries[path] = summarize(raw, path)
        return summary, raw
