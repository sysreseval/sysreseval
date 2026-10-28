"""Tests of sreweb.agent.results.ArchiveIndex (the last archived evaluation of each project, the
Watch page and the Evaluation tab of the instructors) on hand-written archives, without the agent."""
import asyncio
import logging
import os

import pytest

from SRE import params
from sreweb.agent.results import ArchiveIndex
from test_archive_summary import RLN, archive_dict, write_archive

NAME = f'20261025100102_{RLN}.zst'


def run(coro):
    return asyncio.run(coro)


class TestArchiveIndex:
    def test_scan_kept_until_invalidated(self, tmp_path):
        write_archive(tmp_path, NAME, archive_dict())
        idx = ArchiveIndex([str(tmp_path), str(tmp_path / 'missing')], ttl=60)

        async def go():
            await idx.refresh()
            assert idx.scans == 1 and idx.summary(RLN).grade == 1.0
            await idx.refresh()
            assert idx.scans == 1
            idx.invalidate()
            await idx.refresh()
            assert idx.scans == 2
            summary, raw = await idx.archive(RLN)
            assert summary.grade == 1.0 and raw['tests'] and idx.summary('nope') is None
            assert await idx.archive('nope') is None
        run(go())

    def test_rewritten_archive_is_read_again(self, tmp_path):
        """A new evaluation is a new file, but an archive written again at the same path (two
        evaluations in the same second, sre re-eval -p '') must not keep its old summary."""
        path = write_archive(tmp_path, NAME, archive_dict())
        idx = ArchiveIndex([str(tmp_path)], ttl=60)

        async def go():
            await idx.refresh()
            assert (await idx.archive(RLN))[0].grade == 1.0
            write_archive(tmp_path, NAME, archive_dict(total_grade_exo_eval=2.5, errors=[]))
            later = os.stat(path).st_mtime_ns + 1_000_000
            os.utime(path, ns=(later, later))
            idx.invalidate()
            await idx.refresh()
            assert idx.summary(RLN).grade == 2.5
            summary, raw = await idx.archive(RLN)
            assert summary.grade == 2.5 and raw['errors'] == ()
        run(go())

    def test_fresh_scan_still_summarises_a_wanted_project(self, tmp_path):
        """The Evaluation tab refreshes for one project: a Watch poll within the ttl must not
        show "never" for the others, whose archives that scan did not summarise."""
        other = RLN.replace('alice', 'bob')
        write_archive(tmp_path, NAME, archive_dict())
        write_archive(tmp_path, f'20261025100102_{other}.zst', archive_dict(**{params.running_lab_name_keyword: other}))
        idx = ArchiveIndex([str(tmp_path)], ttl=60)

        async def go():
            await idx.refresh({RLN})
            assert idx.scans == 1 and idx.summary(RLN) is not None and idx.summary(other) is None
            await idx.refresh({other})
            assert idx.scans == 1 and idx.summary(other).running_lab_name == other
        run(go())

    def test_unreadable_archive_logged_once(self, tmp_path, caplog):
        path = tmp_path / NAME
        path.write_bytes(b'not an archive')
        idx = ArchiveIndex([str(tmp_path)], ttl=60)

        async def go():
            with caplog.at_level(logging.WARNING, logger='sreweb.agent'):
                for _ in range(3):
                    await idx.refresh(force=True)
                assert idx.summary(RLN) is None and await idx.archive(RLN) is None
                # the file replaced by a readable one: read
                write_archive(tmp_path, NAME, archive_dict())
                await idx.refresh(force=True)
                assert idx.summary(RLN).grade == 1.0
            messages = [r.message for r in caplog.records if r.message.startswith('cannot read the archive')]
            assert len(messages) == 1 and str(path) in messages[0]
        run(go())
