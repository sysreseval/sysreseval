"""The reports of the Archives page of the portal (``POST /v1/reports/{kind}``): the pure helpers
around ``sre report``, which builds the spreadsheet of ``sre sheet`` (``sheet``), the zip of the
PDF reports and the summary of ``sre outline`` (``outline``) or that summary spreadsheet alone
(``summary``, what ``sre outline -o`` gives) from the JSON archive records the portal rebuilt from
its database.  The request body is ``{"records": [...], "options": {...}}``;
the options become the flags of the command, the file name of the download is computed here from
the records (the stderr of ``sre report`` is its message channel, not a place for a name)."""
import re
from datetime import datetime

from SRE.archive_summary import lab_name_of_rln

#: kind -> the content type of the download.
ODS = 'application/vnd.oasis.opendocument.spreadsheet'
KINDS = {'sheet': ODS, 'outline': 'application/zip', 'summary': ODS}
EXTENSIONS = {'sheet': 'ods', 'outline': 'zip', 'summary': 'ods'}
PREFIXES = {'sheet': 'evaluations', 'outline': 'reports', 'summary': 'summary'}
#: The kinds that are one spreadsheet (no PDF).
SPREADSHEETS = frozenset({'sheet', 'summary'})
#: option of the request -> the flag of ``sre report`` (every option is a boolean).
OPTION_FLAGS = {'separate_instances': '--separate-instances', 'bonus_in_prefix': '--bonus-in-prefix',
                'no_timeline': '--no-timeline', 'remaining_time': '--remaining-time', 'no_parts': '--no-parts'}
#: The options of the PDF reports alone: dropped for a spreadsheet.
PDF_ONLY = frozenset({'no_timeline', 'remaining_time', 'no_parts'})
#: The biggest request body (the app caps the other requests at the size of the answers).
MAX_REPORT_BODY = 64 << 20
MAX_FILENAME_PART = 60


def parse_report_request(data) -> tuple[list, dict]:
    """``(records, options)`` of a request body: a non-empty list of records (dicts) and the
    boolean options of ``OPTION_FLAGS``; ``ValueError`` otherwise."""
    if not isinstance(data, dict):
        raise ValueError("a JSON object is expected")
    records = data.get('records')
    if not isinstance(records, list) or not records:
        raise ValueError("records: a non-empty list is expected")
    if not all(isinstance(r, dict) for r in records):
        raise ValueError("records: every record must be an object")
    options = data.get('options')
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ValueError("options: an object is expected")
    unknown = set(options) - set(OPTION_FLAGS)
    if unknown:
        raise ValueError(f"unknown option(s): {', '.join(sorted(unknown))}")
    for key, value in options.items():
        if not isinstance(value, bool):
            raise ValueError(f"option {key}: true or false is expected")
    return records, dict(options)


def report_flags(kind: str, options: dict) -> list:
    """The flags of ``sre report`` for *options* (in the order of ``OPTION_FLAGS``; the PDF
    options left out of a spreadsheet, ``sheet`` or ``summary``)."""
    return [flag for key, flag in OPTION_FLAGS.items()
            if options.get(key) and not (kind in SPREADSHEETS and key in PDF_ONLY)]


def _lab_part(records: list) -> str:
    """The short name of the lab when the records are of one lab (``dhcp`` for
    ``sre/dhcp.py``), made safe for a file name; ``''`` otherwise."""
    labs = set()
    for r in records:
        lab = r.get('lab') or lab_name_of_rln(str(r.get('running_lab_name') or ''))
        if lab:
            labs.add(str(lab))
    if len(labs) != 1:
        return ''
    short = labs.pop().rpartition('/')[2].removesuffix('.py')
    return re.sub(r'[^A-Za-z0-9._-]+', '_', short).strip('_')[:MAX_FILENAME_PART]


def report_filename(kind: str, records: list, now: datetime | None = None) -> str:
    """``evaluations_<lab>_<YYYYmmdd-HHMM>.ods`` / ``reports_<lab>_<YYYYmmdd-HHMM>.zip`` /
    ``summary_<lab>_<YYYYmmdd-HHMM>.ods`` when the records are of one lab, without the lab part
    otherwise."""
    now = now or datetime.now()
    lab = _lab_part(records)
    middle = f'_{lab}' if lab else ''
    return f"{PREFIXES[kind]}{middle}_{now.strftime('%Y%m%d-%H%M')}.{EXTENSIONS[kind]}"
