#!/opt/SRE/venv/bin/python3
import argparse
import gettext
import os
import re
import sys
import logging
from pathlib import Path

from SRE import params

# Kathara sets Docker connection pool size = cpu_count(), but SRE runs up to
# max_docker_concurrency concurrent operations — suppress the harmless overflow warning.
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
from SRE.utils import error_quit
from SRE.utils_privileges import drop_privileges_temporarily, drop_privileges_permanently


# i18n — load French translations when LANG is set to a French locale.
# Searches <repo>/locale/ (development) then <main_sre_dir>/locale/ (production).
def _setup_i18n():
    for _d in [Path(__file__).resolve().parent.parent / 'locale', Path(params.main_sre_dir) / 'locale']:
        try:
            return gettext.translation('sre', localedir=str(_d)).gettext
        except FileNotFoundError:
            pass
    return lambda s: s


_ = _setup_i18n()
from SRE.command.connect import action_connect
from SRE.command.exec_ import action_exec
from SRE.command.state import action_state
from SRE.command.eval import action_eval
from SRE.command.list import action_list
from SRE.command.make_titles import action_make_titles
from SRE.command.start import action_start
from SRE.command.wipe import action_wipe
from SRE.command.stop import action_stop
from SRE.command.set_exam import action_set_exam
from SRE.command.del_exam import action_del_exam
from SRE.command.pre_start_exam import action_pre_start_exam
from SRE.command.start_exam import action_start_exam
from SRE.command.eval_exam import action_eval_exam
from SRE.command.cat import action_cat
from SRE.command.sheet import action_sheet
from SRE.command.re_eval import action_re_eval
from SRE.command.check_eval import action_check_eval
from SRE.command.check import action_check
from SRE.command.export import action_export
from SRE.command.eval_all import action_eval_all
from SRE.command.watch import action_watch
from SRE.command.end_exam import action_end_exam
from SRE.command.outline import action_outline
from SRE.command.save_records import action_save_records
from SRE.command.preload_images import action_preload_images
from SRE.params import SRE

_CATEGORY_HEADERS = {
    'start': _('Dual commands, used both by sysreseval for administration:'),
    'exec': _('Admin-only commands:'),
    'set-exam': _('Admin-only commands for exam management:'),
    'cat': _('Admin-only commands for post-exam management:'),
    'list': _('Internal (only used by sysreseval GUI):'),
}


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def _format_action(self, action):
        result = super()._format_action(action)
        if not action.option_strings and action.dest in _CATEGORY_HEADERS:
            header = _CATEGORY_HEADERS[action.dest]
            result = '\n' + header + '\n' + result
        return result


def parse_args():
    parser = argparse.ArgumentParser(
        prog='SRE',
        description='SRE',
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help=_('show this help message and exit'))

    parser.add_argument('--user', action='store_true', help=_('started from SRE-wrapper'))
    parser.add_argument('--debug', action='store_true', help=_('print debug messages on stderr'))
    parser.add_argument('--version', action='version', version=params.sre_version,
                        help=_('display version and exit'))

    #    parser.add_argument("-l", metavar='lab', help=_("lab directory"))

    subparsers = parser.add_subparsers(title=_('Actions'), dest='action')

    # --- lab lifecycle ---
    parser_start = subparsers.add_parser('start', help=_('Start a lab'))
    parser_start.add_argument('-d', '--data', metavar='src_data_file',
                              help=_('use this data file (rather than create a new one)'))
    parser_start.add_argument('-p', '--path', action='store_true',
                              help=_('the lab argument is a path to the lab directory'))
    parser_start.add_argument('lab', metavar='lab', help=_('lab name or path to the lab directory'))
    parser_start.add_argument('data_version', metavar='data_version', nargs='?', default=None,
                              help=_(
                                  'optional version/seed passed to Data.generate() (privileged only; incompatible with --data)'))
    flavor_group = parser_start.add_mutually_exclusive_group()
    flavor_group.add_argument('--flavor', metavar='key:value', nargs='+',
                              help=_('flavor field values, e.g. --flavor a:1 b:foo'))
    flavor_group.add_argument('--flavor-json', metavar='flavor_json',
                              help=_('flavor as JSON dict (used internally by the GUI)'))
    flavor_group.add_argument('--set-flavor-name', metavar='flavor_name',
                              help=_(
                                  'use a named Flavor preset defined as a class variable on the Flavor class (privileged only)'))
    parser_start.add_argument('--debug-project', dest='debug_project', action='store_true',
                              help=_('start the project in debug mode (privileged only): exposes all grade scopes, '
                                     'lifts user-mode restrictions, surfaces every machine'))
    parser_start.add_argument('--xauth-file', metavar='x-authority-file', dest='xauth_file',
                              default=None,
                              help=_('read the X11 magic cookie from this X authority file instead of '
                                     '$SRE_XAUTH_COOKIE (privileged only)'))

    parser_stop = subparsers.add_parser('stop', help=_('Stop a running project'))
    parser_stop.add_argument('running_lab', metavar='running_lab', help=_('running lab name'))

    subparsers.add_parser('wipe', help=_('Remove all files and stop kathara'))

    parser_connect = subparsers.add_parser('connect', help=_('Connect to a device (with the predefined command)'))
    parser_connect.add_argument('--shell', metavar='shell', default=None,
                                help=_('shell to launch instead of the machine default (privileged only)'))
    parser_connect.add_argument('--exec', metavar='argument', dest='exec_cmd', nargs=argparse.REMAINDER,
                                help=_('execute a command via the shell and return'))
    parser_connect.add_argument('--no-records', action='store_true', dest='no_records',
                                help=_('do not record the session (privileged only)'))
    parser_connect.add_argument('running_lab', metavar='running_lab', help=_('running lab name'))
    parser_connect.add_argument('device', help=_('target device'))

    parser_eval = subparsers.add_parser('eval', help=_('Evaluate the project'))
    parser_eval.add_argument('-p', '--path', metavar='path', help=_('path to the lab directory'))
    parser_eval.add_argument('--auto-eval', dest='auto_eval', action='store_true',
                             help=_('user-triggered self-evaluation: enable cooldown, log timestamp, return result'))
    parser_eval.add_argument('running_lab', metavar='running_lab',
                             help=_('running lab name or path to the lab directory'))

    parser_state = subparsers.add_parser('state', help=_('Apply a state'))
    parser_state.add_argument('running_lab', metavar='running_lab', help=_('running lab name'))
    parser_state.add_argument('state', help=_('name of the state to apply'))

    parser_exec = subparsers.add_parser('exec', help=_('Execute a command in a device (privileged only)'))
    parser_exec.add_argument('--shell', metavar='shell', default=None,
                             help=_('shell to use instead of the default'))
    parser_exec.add_argument('running_lab', metavar='running_lab', help=_('running lab name'))
    parser_exec.add_argument('device', help=_('target device'))
    parser_exec.add_argument('command', nargs=argparse.REMAINDER, help=_('command to execute'))

    parser_eval_all = subparsers.add_parser('eval-all', help=_('Evaluate all running projects concurrently'))
    parser_eval_all.add_argument('--display-grades', action=argparse.BooleanOptionalAction,
                                 default=True, help=_('print grades to stdout (default: true)'))

    parser_check = subparsers.add_parser('check', help=_('Check a lab module for errors'))
    parser_check.add_argument('path', metavar='path', help=_('path to the lab file or directory'))
    parser_check.add_argument('state', metavar='state', nargs='?', default=None,
                              help=_('also check this state method of NetScheme'))

    parser_watch = subparsers.add_parser('watch', help=_('Monitor exam archive directories in real time'))
    parser_watch.add_argument('dirs', nargs='+', metavar='dir', help=_('directories to scan for .zst archives'))
    parser_watch.add_argument('--timeout', type=int, default=params.default_inactivity_threshold_in_watch_command,
                              metavar='seconds', help=_('inactivity alert threshold (default: 90)'))
    parser_watch.add_argument('--interval', type=int,
                              default=params.default_dashboard_refresh_interval_in_watch_command,
                              metavar='seconds',
                              help=_(
                                  f'dashboard refresh interval (default: {params.default_dashboard_refresh_interval_in_watch_command})'))

    parser_preload = subparsers.add_parser('preload-images',
                                           help=_('Pre-pull Docker images referenced by lab files'))
    parser_preload.add_argument('--random-delay', type=int, default=0, metavar='seconds',
                                help=_('wait a random delay of 0 to N seconds before pulling'))
    parser_preload.add_argument('paths', nargs='+', metavar='file_or_dir',
                                help=_('lab .py file(s) or director(ies) to scan recursively'))

    parser_make_titles = subparsers.add_parser(
        'make-titles',
        help=_('Generate titles.json file(s) for a lab directory'))
    parser_make_titles.add_argument('directory', help=_('directory to scan'))
    _mt_group = parser_make_titles.add_mutually_exclusive_group()
    _mt_group.add_argument('-o', '--output-file', metavar='FILE',
                           help=_('write all titles to FILE instead of <directory>/titles.json'))
    _mt_group.add_argument('-r', '--recursive', action='store_true',
                           help=_('recursively scan subdirectories, writing one titles.json per directory'))

    # --- exam management ---
    parser_set_exam = subparsers.add_parser('set-exam', help=_('Create or update the exam configuration'))
    parser_set_exam.add_argument('--labs', nargs='+', metavar='lab[:flavor]',
                                 help=_('lab names, optionally with a flavor preset (e.g. lab1:hard lab2)'))
    parser_set_exam.add_argument('--start-after', metavar='datetime',
                                 help=_('exam opens after this datetime (ISO format, e.g. 2026-06-01T09:00)'))
    parser_set_exam.add_argument('--end-before', metavar='datetime',
                                 help=_('exam closes before this datetime (ISO format)'))
    parser_set_exam.add_argument('--duration', metavar='minutes',
                                 help=_('maximum exam duration in minutes; prefix with + or - to adjust the existing duration (e.g. +30, -15)'))
    parser_set_exam.add_argument('--eval-interval', type=int, metavar='seconds',
                                 help=_('duration between two evaluations'))
    parser_set_exam.add_argument('--record-sessions', type=lambda x: x.lower() not in ('false', '0', 'no'),
                                 default=None, metavar='bool', help=_('record terminal sessions (default: true)'))

    subparsers.add_parser('del-exam', help=_('Remove exam configuration and wipe all projects'))

    parser_save_records = subparsers.add_parser('save-records',
                                                help=_('Archive session records of running projects into a directory'))
    parser_save_records.add_argument('directory', metavar='directory',
                                     help=_('destination directory for the record archives'))
    parser_save_records.add_argument('--only-last-record', action='store_true', default=False,
                                     help=_(
                                         'delete previous record archives for the same running project after saving'))

    # --- archive inspection ---
    parser_cat = subparsers.add_parser('cat', help=_('Print the content of evaluation archive files'))
    parser_cat.add_argument('--data', action='store_true', help=_('show the data field'))
    parser_cat.add_argument('--tests', action='store_true', help=_('show the tests field'))
    parser_cat.add_argument('--errors', action='store_true', help=_('show the errors field'))
    parser_cat.add_argument('--answers', action='store_true', help=_('show the answers field'))
    parser_cat.add_argument('--grades', action='store_true', help=_('show grades (grade_list, total_grade, total_max)'))
    parser_cat.add_argument('--files', dest='show_files', action='store_true', help=_('show files saved in archive'))
    parser_cat.add_argument('--extract-files', dest='extract_files', action='store_true',
                            help=_('extract files saved in archive to current directory'))
    parser_cat.add_argument('--json', action='store_true', help=_('output as a single JSON-encoded dict per file'))
    parser_cat.add_argument('files', nargs='+', metavar='file', help=_('archive file(s) to read'))

    parser_check_eval = subparsers.add_parser('check-eval',
                                              help=_('Compare re-graded results with stored grades in archives'))
    parser_check_eval.add_argument('--srelab', '-s', metavar='srelab',
                                   help=_('path to srelab.py or directory (default: taken from archive)'))
    parser_check_eval.add_argument('files', nargs='+', metavar='file',
                                   help=_('archive file(s) to check'))

    parser_re_eval = subparsers.add_parser('re-eval',
                                           help=_('Re-grade evaluation archives with a (possibly updated) srelab.py'))
    parser_re_eval.add_argument('--srelab', '-s', required=True, metavar='srelab',
                                help=_('path to srelab.py or to a directory containing it'))
    parser_re_eval.add_argument('--prefix', '-p', required=True, metavar='prefix',
                                help=_('prefix prepended to each output filename'))
    parser_re_eval.add_argument('--output-dir', '-d', metavar='dir',
                                help=_('output directory (default: current directory)'))
    parser_re_eval.add_argument('-r', '--recursive', action='store_true',
                                help=_('recurse into subdirectories when searching for .zst archives'))
    parser_re_eval.add_argument('files', nargs='+', metavar='file_or_dir',
                                help=_('archive file(s) or director(ies) of .zst archives to re-evaluate'))

    parser_sheet = subparsers.add_parser('sheet', help=_('Export evaluation archives to a LibreOffice ODS spreadsheet'))
    parser_sheet.add_argument('-o', '--output', metavar='file', required=True, help=_('output .ods file'))
    parser_sheet.add_argument('-r', '--recursive', action='store_true',
                              help=_('recurse into subdirectories when searching for .zst archives'))
    parser_sheet.add_argument('files', nargs='+', metavar='file_or_dir',
                              help=_('archive file(s) or director(ies) of .zst archives'))

    parser_outline = subparsers.add_parser('outline',
                                           help=_('Generate per-student PDF reports and a summary ODS spreadsheet'))
    parser_outline.add_argument('-o', '--output-file', metavar='file',
                                help=_('output .ods summary file (omit to skip ODS generation)'))
    parser_outline.add_argument('-d', '--pdf-directory', metavar='pdf_dir',
                                help=_('output directory for PDF reports (omit to skip PDF generation)'))
    parser_outline.add_argument('--lang', metavar='lang', default=None,
                                help=_('force language for PDF output (e.g. en, fr)'))
    parser_outline.add_argument('-r', '--recursive', action='store_true',
                                help=_('recurse into subdirectories when searching for .zst archives'))
    parser_outline.add_argument('--no-timeline', action='store_true',
                                help=_('omit the evaluation history table from PDF reports'))
    parser_outline.add_argument('--remaining-time', action='store_true',
                                help=_('include the time remaining column in the evaluation history table'))
    parser_outline.add_argument('--no-parts', action='store_true',
                                help=_('do not group PDF grade rows by GradePart (flat list, no subtotals)'))
    parser_outline.add_argument('--users-file', metavar='users_file', default=None,
                                help=_(
                                    'user list file with columns: LOGIN NAME EMAIL (adds Name/Email to PDFs and ODS)'))
    parser_outline.add_argument('files', nargs='+', metavar='file_or_dir',
                                help=_('archive file(s) or director(ies) of .zst archives'))

    # --- plumbing / internal ---
    parser_list = subparsers.add_parser('list', help=_('List all available projects'))
    parser_list.add_argument('--with-titles', action='store_true',
                             help=_('emit a list of {name, title} objects, '
                                    'reading translated titles from per-directory titles.json'))

    parser_export = subparsers.add_parser('export',
                                          help=_(
                                              'Export a running project as a Kathara zip archive (base64 on stdout)'))
    parser_export.add_argument('running_lab', metavar='running_lab', help=_('running lab name'))
    parser_export.add_argument('--sep', type=int, default=3, metavar='N',
                               help=_('schema node separation level 0-9 (default: 3)'))
    parser_export.add_argument('--curved', action='store_true',
                               help=_('draw schema edges as curved lines (default: straight)'))
    parser_export.add_argument('--shapes', action='store_true',
                               help=_('draw schema nodes as geometric shapes instead of icons'))
    parser_export.add_argument('--reverse', action='store_true',
                               help=_('reverse node insertion order in the schema'))
    parser_export.add_argument('--random-seed', type=int, default=None, metavar='N',
                               help=_('random seed for node order permutation in the schema'))

    subparsers.add_parser('eval-exam', help=_('Evaluate all running exam projects concurrently'))
    subparsers.add_parser('end-exam', help=_('Mark the exam as ended and run a final evaluation of all projects'))
    subparsers.add_parser('pre-start-exam', help=_('Pre-start exam: stop other projects and start exam projects'))
    subparsers.add_parser('start-exam',
                          help=_('Do pre-start-exam and mark the exam as started (sets started_at timestamp)'))

    a = parser.parse_args()
    if a.action is None:
        parser.print_help()
        sys.exit(1)
    if a.user and a.debug:
        error_quit(_("--user and --debug are mutually exclusive"))
    return a


# with open('/tmp/sre-log', 'a') as _f:
#     from datetime import datetime as _dt
#     print(f"{_dt.now().isoformat(timespec='seconds')} {' '.join(sys.argv[1:])}", file=_f)


if '--version' in sys.argv[1:]:
    print(params.sre_version)
    sys.exit(0)

uid = os.geteuid()
if uid != 0 and uid != params.sre_uid:
    if uid not in params.admin_uids:
        gids = set(os.getgroups()) | {os.getegid()}
        if not gids.intersection(params.admin_gids):
            error_quit(_("illegal userid"))

SRE.args = parse_args()

if uid != 0 and uid != params.sre_uid and SRE.args.action not in ('cat', 'check-eval', 're-eval', 'sheet', 'outline'):
    error_quit(_("illegal userid"))

if SRE.args.user:
    if params.use_sudo_user_for_username:
        SRE.username = os.getenv('SUDO_USER', '')
    else:
        SRE.username = os.getenv('USER_USERNAME', '')
else:
    SRE.username = os.getenv('LOGNAME', '')

_VALID_USERNAME = re.compile(r'^[a-zA-Z0-9._-]+$')

if not _VALID_USERNAME.match(SRE.username):
    error_quit(_("invalid username: '{}'").format(SRE.username))

if os.getenv('SUDO_USER'):
    # Called via sudo: must come through sre-wrapper (which sets --user), unless it's an admin
    # A direct "sudo sre" without --user is rejected immediately
    if not SRE.args.user:
        error_quit(_("must be launched via sre-wrapper"))

    def _check_launched_from_wrapper():
        wrapper_real = os.path.realpath(params.sre_wrapper)
        pid = os.getppid()
        for _ in range(6):
            try:
                # exe readlink may be denied when the target process runs as a
                # different uid (e.g. root sudo vs. dropped-privilege sre).
                # Treat EACCES/EPERM as "not a match" and fall through to the
                # cmdline check, which is world-readable.
                try:
                    if os.readlink(f'/proc/{pid}/exe') == wrapper_real:
                        return True
                except OSError:
                    pass
                # Also handle shell-script wrapper: kernel sets argv as
                # [interpreter, script_path, ...], so check cmdline args.
                with open(f'/proc/{pid}/cmdline', 'rb') as f:
                    cmdline = [a.decode(errors='replace')
                               for a in f.read().split(b'\x00') if a]
                if any(os.path.realpath(a) == wrapper_real
                       for a in cmdline[:3]):
                    return True
                ppid = None
                with open(f'/proc/{pid}/status') as f:
                    for line in f:
                        if line.startswith('PPid:'):
                            ppid = int(line.split()[1])
                            break
                if ppid in (None, 0, 1, pid):
                    break
                pid = ppid
            except OSError:
                break
        return False


    if not _check_launched_from_wrapper():
        error_quit(_("must be launched via sre-wrapper"))

if uid == 0:
    # Kathara's PrivilegeHandler is a singleton that captures os.geteuid() on first
    # instantiation. If it initialises after we drop euid to sre_uid, raise_privileges()
    # will only ever restore to sre_uid — never to root. Force it now, while still root.
    from Kathara.auth.PrivilegeHandler import PrivilegeHandler

    PrivilegeHandler.get_instance()

if params.allow_privileged_machines and SRE.args.action in ('start', 'start-exam', 'pre-start-exam', 'connect', 'exec',
                                                            'eval', 'eval-all',
                                                            'eval-exam', 'state', 'stop', 'wipe'):
    drop_privileges_temporarily()
else:
    drop_privileges_permanently()

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

match SRE.args.action:
    case 'wipe':
        action_wipe()
    case 'list':
        action_list(with_titles=SRE.args.with_titles)
    case 'make-titles':
        action_make_titles(SRE.args.directory, SRE.args.output_file, SRE.args.recursive)
    case 'start':
        action_start()
    case 'check':
        action_check()
    case 'connect':
        action_connect()
    case 'exec':
        action_exec()
    case 'state':
        action_state()
    case 'eval':
        action_eval()
    case 'eval-all':
        action_eval_all()
    case 'stop':
        action_stop()
    case 'eval-exam':
        action_eval_exam()
    case 'set-exam':
        action_set_exam()
    case 'del-exam':
        action_del_exam()
    case 'pre-start-exam':
        action_pre_start_exam()
    case 'start-exam':
        action_start_exam()
    case 're-eval':
        action_re_eval()
    case 'check-eval':
        action_check_eval()
    case 'watch':
        action_watch()
    case 'sheet':
        action_sheet()
    case 'cat':
        action_cat()
    case 'export':
        action_export()
    case 'end-exam':
        action_end_exam()
    case 'outline':
        action_outline()
    case 'save-records':
        action_save_records()
    case 'preload-images':
        action_preload_images()

# lab = Lab(name='a', path="/home/etudiant/tp-arp")
# Kathara.get_instance().deploy_lab(lab)
