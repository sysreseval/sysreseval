"""``sre report``: the spreadsheet of ``sre sheet`` or the PDF reports of ``sre outline``, built
out of JSON archive records read on stdin instead of ``.zst`` files, written on stdout.

Internal: what the web agent runs for the Archives page of the portal.  The records are those of
``archive_summary.archive_record`` (what the agents send to the portal, what its database keeps
of every archive), rebuilt by the portal from its rows for the projects an instructor selected;
``archive_summary.raw_from_record`` turns each into the pseudo archive the collectors of the two
commands read.  Nothing but the file goes to stdout (the agent answers it as a download), the
warnings go to stderr.  Privileged only (``--user`` refused), like ``sheet`` and ``outline``.
"""
import io
import json
import sys
import tempfile
import zipfile
from pathlib import Path

from ..archive_summary import raw_from_record
from ..params import SRE
from ..utils import error_quit, user_not_allowed
from . import outline, sheet
from .sheet import _setup_i18n

_ = _setup_i18n()

KINDS = ('sheet', 'outline')
#: The summary spreadsheet of the PDF reports, inside the zip (what ``sre outline -o`` writes).
OUTLINE_SUMMARY_NAME = 'outline.ods'


def _member_name(path: Path) -> str:
    """The name of a PDF inside the zip: its file name (built by ``outline._safe_filename``), with
    nothing a zip reader could take as a path."""
    name = path.name.replace('\0', '_').replace('/', '_').replace('\\', '_')
    return '_' if name in ('', '.', '..') else name


def generate_report(kind: str, records: list, *, lang: str | None = None, separate_instances: bool = False,
                    bonus_in_prefix: bool = False, no_timeline: bool = False, remaining_time: bool = False,
                    no_parts: bool = False, warn=None) -> bytes:
    """The bytes of the report of *kind* for *records* (``archive_record`` dicts): the ODS of
    ``sheet.build_sheet`` for ``sheet``; for ``outline`` a zip holding the PDFs of
    ``outline.build_outline`` (sorted by name) then ``outline.ods``, the summary.  A record
    without ``running_lab_name`` is skipped through *warn*; ``ValueError`` on an unknown kind or
    when no record is usable."""
    if kind not in KINDS:
        raise ValueError(f"unknown report kind: {kind}")
    warn = warn or (lambda text: None)
    raws = []
    for record in records:
        if not isinstance(record, dict) or not record.get('running_lab_name'):
            warn(_("warning: a record without running_lab_name is skipped"))
            continue
        raws.append(raw_from_record(record))
    if not raws:
        raise ValueError(_("no records to process"))
    if kind == 'sheet':
        buf = io.BytesIO()
        sheet.build_sheet([sheet._record_of_raw(raw) for raw in raws], buf,
                          separate_instances=separate_instances, bonus_in_prefix=bonus_in_prefix)
        return buf.getvalue()
    with tempfile.TemporaryDirectory(prefix='sre-report-') as tmp:
        pdf_dir = Path(tmp) / 'pdf'
        pdf_dir.mkdir()
        summary = Path(tmp) / OUTLINE_SUMMARY_NAME
        written = outline.build_outline([outline._record_of_raw(raw) for raw in raws], pdf_dir=pdf_dir,
                                        summary_path=summary, lang=lang, separate_instances=separate_instances,
                                        bonus_in_prefix=bonus_in_prefix, no_timeline=no_timeline,
                                        remaining_time=remaining_time, no_parts=no_parts, warn=warn)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(written, key=lambda p: p.name):
                archive.write(path, arcname=_member_name(path))
            archive.write(summary, arcname=OUTLINE_SUMMARY_NAME)
        return buf.getvalue()


def action_report():
    user_not_allowed()
    args = SRE.args
    try:
        data = json.loads(sys.stdin.buffer.read())
    except ValueError as e:
        error_quit(_("invalid JSON on stdin: {e}").format(e=e))
    records = data.get('records') if isinstance(data, dict) else None
    if not isinstance(records, list) or not records:
        error_quit(_("no records to process"))
    try:
        out = generate_report(args.kind, records, lang=args.lang, separate_instances=bool(args.separate_instances),
                              bonus_in_prefix=bool(args.bonus_in_prefix), no_timeline=bool(args.no_timeline),
                              remaining_time=bool(args.remaining_time), no_parts=bool(args.no_parts),
                              warn=lambda text: print(text, file=sys.stderr))
    except ValueError as e:
        error_quit(str(e))
    if args.output and args.output != '-':
        Path(args.output).write_bytes(out)
    else:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
