#!/usr/bin/env python3
"""web-purge-log: remove the connection log of ``sre-web`` older than N days (365 by default):
the rotated files next to ``[access_log] file`` (``access.log.YYYY-MM-DD``, or the files of
logrotate) and the rows of the ``[access_log.database]`` table, both read from ``web.toml``.
The portal itself keeps ``keep`` days of each store while it runs (400 by default); this script
applies a retention of its own, from a cron job or a timer of the host, with the Python of the
portal (PyMySQL for the database):

    /opt/sre/venv/bin/python3 /opt/sre/scripts/web-purge-log.py [--days 365] [--dry-run] [--optimize]

The current file is never touched (the portal writes it); a rotated file goes by its modification
time.  ``--optimize`` rebuilds the table after the deletion, so that the deleted rows no longer
occupy its file (a short lock of the table; the portal's writer retries meanwhile).  Exit status:
0, 1 when a store could not be purged (the reason on stderr; the other store is still done), 2 on
a usage or configuration error.  Nothing happens when ``[access_log]`` names no file and no database.
"""
import argparse
import sys
import time
from pathlib import Path

try:
    import sreweb  # noqa: F401            (installed: the Debian package)
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))    # a checkout: ../src

from sreweb.config import ConfigError, load_web_config  # noqa: E402
from sreweb.portal.defaults import default_config_file  # noqa: E402

DEFAULT_DAYS = 365
BATCH = 10000          # rows per DELETE


def rotated_files(log_file: str) -> list:
    """The rotated copies of *log_file*: the ``<name>.<suffix>`` files of its directory (the
    ``access.log.2026-10-01`` of the portal, the ``access.log.1.gz`` of logrotate), the file
    itself excluded."""
    path = Path(log_file)
    return sorted(p for p in path.parent.glob(path.name + '.*') if p.is_file())


def purge_files(log_file: str, cutoff: float, *, dry_run: bool = False) -> list:
    """Remove the rotated files last modified before *cutoff* (seconds since the epoch); the
    paths removed (or to remove, with *dry_run*)."""
    removed = []
    for path in rotated_files(log_file):
        if path.stat().st_mtime < cutoff:
            if not dry_run:
                path.unlink()
            removed.append(path)
    return removed


def purge_database(db, cutoff: float, *, dry_run: bool = False, optimize: bool = False, connect=None) -> int:
    """Delete the rows of the table of *db* (an ``AccessDatabaseConfig``) whose ``ts`` is before
    *cutoff*, ``BATCH`` at a time; the number deleted (or to delete, with *dry_run*).  *connect*
    replaces the driver's connection (the tests)."""
    from sreweb.portal.accessdb import connector, utc_datetime
    if connect is None:
        connect, _ = connector(db)
    before = utc_datetime(cutoff)
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM `{db.table}` WHERE ts < %s", (before,))
            count = int(cur.fetchone()[0])
            if dry_run:
                return count
            deleted = 0
            while True:
                cur.execute(f"DELETE FROM `{db.table}` WHERE ts < %s LIMIT {BATCH}", (before,))
                conn.commit()
                affected = cur.rowcount if cur.rowcount is not None else 0
                deleted += max(affected, 0)
                if affected < BATCH:
                    break
            if optimize:
                cur.execute(f"OPTIMIZE TABLE `{db.table}`")
                cur.fetchall()
                conn.commit()
        return deleted
    finally:
        conn.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='web-purge-log', description=__doc__.split('\n\n')[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', default=default_config_file(), help="the web.toml of the portal")
    parser.add_argument('--days', type=int, default=DEFAULT_DAYS,
                        help=f"remove what is older than this many days ({DEFAULT_DAYS})")
    parser.add_argument('--dry-run', action='store_true', help="only say what would be removed")
    parser.add_argument('--optimize', action='store_true', help="rebuild the table after the deletion (OPTIMIZE TABLE)")
    parser.add_argument('--files-only', action='store_true', help="the rotated files, not the database")
    parser.add_argument('--database-only', action='store_true', help="the database, not the files")
    args = parser.parse_args(argv)
    if args.days < 1:
        parser.error("--days must be at least 1")
    if args.files_only and args.database_only:
        parser.error("--files-only and --database-only exclude each other")
    try:
        cfg = load_web_config(args.config)
    except ConfigError as e:
        print(f"web-purge-log: {e}", file=sys.stderr)
        return 2
    log = cfg.access_log
    cutoff = time.time() - args.days * 86400
    verb = "would remove" if args.dry_run else "removed"
    status = 0
    stores = 0
    if log.file and not args.database_only:
        stores += 1
        try:
            removed = purge_files(log.file, cutoff, dry_run=args.dry_run)
            names = ": " + ', '.join(p.name for p in removed) if removed else ""
            print(f"web-purge-log: {verb} {len(removed)} rotated file(s) of {log.file} older than {args.days} days{names}")
        except OSError as e:
            print(f"web-purge-log: {log.file}: {e}", file=sys.stderr)
            status = 1
    if log.database.enabled and not args.files_only:
        stores += 1
        db = log.database
        where = db.unix_socket or f"{db.host}:{db.port}"
        try:
            count = purge_database(db, cutoff, dry_run=args.dry_run, optimize=args.optimize)
            rebuilt = ", table rebuilt" if args.optimize and not args.dry_run else ""
            print(f"web-purge-log: {verb} {count} row(s) of {db.name}.{db.table} on {where} older than {args.days} days{rebuilt}")
        except Exception as e:
            print(f"web-purge-log: database {db.name} on {where}: {e}", file=sys.stderr)
            status = 1
    if not stores:
        print("web-purge-log: nothing to purge ([access_log] names no file and no database, or the store asked is not configured)")
    return status


if __name__ == '__main__':
    sys.exit(main())
