"""The last evaluation of each project of the host, read from the archives of
``params.archive_dirs`` (``SRE.archive_summary``): what the Watch page of the instructors shows
and what the Evaluation tab of an instructor opens on.

On demand only: a refresh scans the directories once (one ``scandir`` per directory, the newest
archive per running lab name by its 14-digit prefix, one ``stat`` per project) and parses the
newest archive of the projects asked for, in a thread; the scan is kept for ``ttl`` seconds (the
Watch page polls every 5 s), a summary as long as its file is the newest one.  Nothing is read
while nobody watches.  A summary is keyed by the path **and the stamp** (mtime, size) of its
file: a new evaluation is a new file, and an archive written again at the same path (two
evaluations in the same second, ``sre re-eval -p ''``) is read again.  An unreadable archive is
logged once and left alone until its file changes.  ``invalidate()`` forces the next scan (after
an evaluation the agent ran).
"""
import asyncio
import logging
import os
import time

from SRE import params
from SRE.archive_summary import (ArchiveSummary, newest_by_running_lab_name, read_archive, scan_archive_dirs,
                                 summarize)

log = logging.getLogger('sreweb.agent')

Stamp = tuple[int, int]        # (st_mtime_ns, st_size) of an archive
Key = tuple[str, Stamp]        # (path, stamp): the identity of an archive's content


class ArchiveIndex:
    def __init__(self, dirs=None, *, ttl: float = 5.0):
        """*dirs*: the archive directories (``params.archive_dirs`` when ``None``)."""
        self.dirs = list(dirs) if dirs is not None else None
        self.ttl = ttl
        self._newest: dict[str, Key] = {}            # running lab name -> its newest archive
        self._summaries: dict[Key, ArchiveSummary] = {}
        self._raw: dict[Key, dict] = {}              # the archives read in full (the Evaluation tab)
        self._failed: dict[str, Stamp] = {}          # the archives that could not be read, by path
        self._scanned_at: float | None = None
        self._lock = asyncio.Lock()
        self.scans = 0

    def _dirs(self) -> list:
        return self.dirs if self.dirs is not None else list(params.archive_dirs)

    def _fresh(self) -> bool:
        return self._scanned_at is not None and time.monotonic() - self._scanned_at < self.ttl

    def invalidate(self):
        self._scanned_at = None

    def _unreadable(self, key: Key) -> bool:
        return self._failed.get(key[0]) == key[1]

    async def refresh(self, rlns=None, *, force: bool = False):
        """Scan the directories unless the last scan is younger than *ttl* (or *force*), then
        summarise the newest archive of the projects of *rlns* (every one when ``None``) that
        has no summary yet (a fresh scan may hold archives summarised for nobody so far)."""
        async with self._lock:
            if force or not self._fresh():
                self._newest = await asyncio.to_thread(self._scan)
                keep = set(self._newest.values())
                self._summaries = {k: s for k, s in self._summaries.items() if k in keep}
                self._raw = {k: r for k, r in self._raw.items() if k in keep}
                self._failed = {p: st for p, st in self._failed.items() if (p, st) in keep}
                self._scanned_at = time.monotonic()
                self.scans += 1
            wanted = set(rlns) if rlns is not None else set(self._newest)
            todo = [key for r in wanted if (key := self._newest.get(r)) is not None
                    and key not in self._summaries and not self._unreadable(key)]
            if todo:
                summaries, failed = await asyncio.to_thread(self._summarize, todo)
                self._summaries.update(summaries)
                self._failed.update(failed)

    def _scan(self) -> dict:
        newest = {}
        for rln, path in newest_by_running_lab_name(scan_archive_dirs(self._dirs())).items():
            try:
                st = os.stat(path)
            except OSError:
                continue
            newest[rln] = (path, (st.st_mtime_ns, st.st_size))
        return newest

    @staticmethod
    def _summarize(keys) -> tuple[dict, dict]:
        """``(summaries, failed)`` of the archives of *keys*: a truncated or foreign file must
        not hide the others, and is not read again until it changes."""
        summaries, failed = {}, {}
        for path, stamp in keys:
            try:
                summaries[(path, stamp)] = summarize(read_archive(path), path)
            except Exception as e:
                log.warning("cannot read the archive %s: %s", path, e)
                failed[path] = stamp
        return summaries, failed

    def summary(self, rln: str) -> ArchiveSummary | None:
        """The summary of the newest archive of *rln* known to the last refresh."""
        key = self._newest.get(rln)
        return self._summaries.get(key) if key else None

    async def archive(self, rln: str) -> tuple | None:
        """``(summary, archive dict)`` of the newest archive of *rln* (refreshing first), or
        ``None`` (no archive, or an unreadable one)."""
        await self.refresh({rln})
        key = self._newest.get(rln)
        if key is None or self._unreadable(key):
            return None
        if key not in self._raw:
            try:
                self._raw[key] = await asyncio.to_thread(read_archive, key[0])
            except Exception as e:
                log.warning("cannot read the archive %s: %s", key[0], e)
                self._failed[key[0]] = key[1]
                return None
        raw = self._raw[key]
        summary = self._summaries.get(key)
        if summary is None:
            summary = self._summaries[key] = summarize(raw, key[0])
        return summary, raw
