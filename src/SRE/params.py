import os
import re
from datetime import datetime
from typing import Literal

from pathlib import Path

sre_uid = 1100
sre_gid = 1100
sre_user = "sre"
docker_gid = 988

admin_uids = []
admin_gids = [2000]

main_sre_dir = "/opt/sre"

# Override main_sre_dir with the actual install root derived from this file's
# location, so a single build/checkout works from any install path. Without
# this, lib_dir stays at the build-time value and `from utils import ...` in
# srelab.py files fails when sre is installed somewhere other than /opt/sre.
# The marker file (src/sre.py) sits in a world-readable directory so this
# probe works whether we're imported by the privileged CLI or by sysreseval
# running as an unprivileged student (lab/ and lib/ are sre:sre-only).
_candidate = Path(__file__).resolve().parent.parent.parent
if (_candidate / "src" / "sre.py").is_file():
    main_sre_dir = str(_candidate)
del _candidate
sre_pub_dir = "/var/lib/sre"
sre_user_public_dir = "/home/sre"

lab_dir = main_sre_dir + "/lab"
lib_dir = main_sre_dir + "/lib"




# debug_mode:
# - allow environment variables SRE_WRAPPER and SRE_PUB_DIR to overcome the default value (insecure)
# - allow "sysreseval --debug"
debug_mode = True #False

# If True, sysreseval will use the last field in the gecos string and save it in the answers
# of the user as email (to be used in the pdfs generated with "sre outline")
email_in_gecos_last_field: bool = True

max_docker_concurrency = 16

display_marks_in_auto_evaluations_by_default = False
use_numerical_marks_by_default = True
default_maximum_mark = 20

# Scope bitmask values for GradeElement.scope. A grade element is visible in
# self-eval (sre eval --auto-eval) if scope & SELF_EVAL_SCOPE, and in non-auto
# eval / outline / sheet if scope & EXO_EVAL_SCOPE.
SELF_EVAL_SCOPE = 1
EXO_EVAL_SCOPE = 2
BOTH_EVAL_SCOPE = SELF_EVAL_SCOPE | EXO_EVAL_SCOPE  # 3
grade_scopes = (SELF_EVAL_SCOPE, EXO_EVAL_SCOPE, BOTH_EVAL_SCOPE)

default_eval_interval_during_exams = 60  # default duration between two evaluations in exam mode
default_eval_interval_without_exam_mode = 60  # default interval (seconds) for eval outside exam mode when the lab does not define eval_interval_without_exam_mode (0 for no periodic evals)
default_save_record_interval_during_exams = 60     # use 0 to disable saving

default_exam_duration = 90  # default exam duration in minutes when "duration" is absent from exam.json


default_inactivity_threshold_in_watch_command = 90  # default inactivity (no eval) from a project before triggering an alert in watch
default_dashboard_refresh_interval_in_watch_command = 1

max_duration_between_exam_pre_start_and_start = 60  # duration in seconds

default_exec_shell = "/bin/bash"

#################################################################################
#
# Security settings
#
#################################################################################

allow_privileged_machines = True
disable_volume_mount_on_root_partition = False

# For identifying the users, use the environment variable SUDO_USER instead of USER_USERNAME
# SUDO_USER is set by sudo itself, thus not spoofable (but in some configurations don't give the current USER variable)
# USER_USERNAME is set by sre-wrapper from USER (spoofable by the user)
use_sudo_user_for_username = False

# Should projects be able to execute commands on the host (which might be useful)
# shell : execution through subprocess.run with shell=True which allow pipes
# split : execution through shlex.split to forbid pipes
# False : no execution permitted on the host
execute_commands_on_host: Literal["shell", "split", False] = "shell"


authorized_src_dir = [main_sre_dir + '/lab', '/home']


#################################################################################
#
# Don't modify parameters below
#
#################################################################################

sre_version = "0.9"
default_docker_image_version = "1.28"
sre_docker_namespace = "sysreseval"

def sre_docker_image(image_name: str = "base") -> str:
    return f"{sre_docker_namespace}/{image_name}:{default_docker_image_version}"

default_docker_image = sre_docker_image()

sre_wrapper = main_sre_dir + "/bin/sre-wrapper"
sysreseval_exe = main_sre_dir + "/bin/sysreseval"
sre_exe = main_sre_dir + "/sbin/sre"

if debug_mode:
    sre_wrapper = os.environ.get("SRE_WRAPPER", sre_wrapper)
    sre_pub_dir = os.environ.get("SRE_PUB_DIR", sre_pub_dir)

sre_projects_dir = sre_pub_dir + "/projects"




archive_dirs = [sre_pub_dir + '/archives']

sre_name_env_variable = "SRE_LAB_NAME"
sre_xauth_cookie_env_variable = "SRE_XAUTH_COOKIE"
sre_host_ip_env_variable = "SRE_HOST_IP"

sre_host_ip = "172.17.0.1"

exetests_path = lib_dir + "/exetests.py"
exetests_machines_path = '/usr/local/sbin/exetests.py'
exetests_env_name = 'EXETESTS'
exetests_separator = '@@@'
default_timeout = 20

exit_code_flavor_form_needed = 3
exit_code_flavor_not_allowed = 4

default_show_nat_network = True
default_host_network_color = "deepskyblue"
default_host_network_name = "Internet"
default_host_network_shape = "hexagon"
default_host_network_exploded = False
default_host_network_edge_relative_length = 1.0

default_machine_shape = "box"
default_network_shape = "ellipse"

pdf_schema_file = "schema.pdf"
pdf_info_file = "informations.pdf"

# External terminal emulator used to open machine connections.
# The command is built as: terminal_cmd_prefix[:-1] + [terminal_title_opt, title] + terminal_cmd_prefix[-1:] + [sre_wrapper, "connect", project, machine]
# xterm / xfce4-terminal use "-e" and "-title"; mate-terminal / gnome-terminal use "--" and "--title"
# terminal_cmd_prefix = ["/usr/bin/xterm", "-e"]
# terminal_title_opt = "-title"
terminal_cmd_prefix = ["/usr/bin/mate-terminal", "--"]
terminal_title_opt = "--title"

# Terminal appearance defaults (overridable via ~/.config/sysreseval)
terminal_font_size = 12  # font size in points
terminal_color_scheme = "black_on_white"  # "white_on_black" or "black_on_white"
content_font_size = 12  # font size in points for information/questions views
system_font_size = 10  # font size in points for menus, titles, labels

graphicdir = main_sre_dir + "/graphics"
thats_all_folks_svg = graphicdir + "/Thats_all_folks.svg"
sysreseval_logo_svg = graphicdir + "/sysreseval.svg"
machine_icon_svg_file = graphicdir + "/machine.svg"
machine_forbidden_icon_svg_file = graphicdir + "/machine-forbidden.svg"
switch_icon_svg_file = graphicdir + "/switch.svg"

exam_only_affix = ["_EXAM_", "_OLD_", "_DRAFT_", "_TESTS_"]

exam_json_name = "exam.json"
exam_json_keyword = "exam_json"
exam_start_after = "start_after"
exam_end_before = "end_before"
exam_eval_interval = "eval_interval"
exam_pre_start_date = "pre_start_date"
exam_started_at = "started_at"
exam_ended_at = "ended_at"
exam_duration = "duration"
exam_labs = "labs"
exam_record_sessions = "record_sessions"


def parse_lab_entry(entry) -> tuple[str, str | None]:
    """Parse a labs entry: new [lab, flavor] list or legacy plain string.
    Returns (lab_cli_arg, flavor_name_or_None)."""
    if isinstance(entry, list):
        return entry[0], entry[1]
    return entry, None  # backward compat with old exam.json


srelab_py_name = "srelab.py"
titles_file_name = "titles.json"
data_json_name = "data.json"
private_dir_name = ".private"
files_dir_name = "files"
private_mount_dir_name = "mnt"
user_public_dir_name = "user_public_dir"
shared_dir_name = "shared"
records_dir_name = "records"
recorder_idle_time_limit = 10  # seconds; passed to asciinema --idle-time-limit to compress idle gaps in .cast files
recorder_config_dir = sre_pub_dir + "/asciinema"  # ASCIINEMA_CONFIG_HOME — avoids asciinema falling back to $HOME/.config (which the sre user cannot write)
use_asciinema_for_records = True  # True: prefer asciinema (fall back to script if missing). False: always record with script(1).
eval_in_progress_name = "eval_in_progress"
auto_eval_log_name = "auto_eval.log"
debug_project_marker_name = "debug_project"
auto_eval_count_keyword = "auto_eval_count"
info_json_name = "info.json"

answer_dir_name = "answers"
answer_file_name = "answers.json"
cheat_file_name = "cheat.json"

hostname_keyword = "hostname"
login_keyword = "login"
fullname_keyword = "fullname"
email_keyword = "email"
language_keyword = "language"

# Languages selectable in the GUI language priority dialog
available_language_in_interface = ['en', 'fr']
language_display_names = {'en': 'English', 'fr': 'Français'}

running_lab_name_keyword = "running_lab_name"
eval_date_keyword = "eval_date"
re_eval_date_keyword = "re_eval_date"

sysreseval_answers_updated_at = 'answers_updated_at'
sysreseval_exam_time_remaining = 'exam_time_remaining'
sysreseval_exam_started_at = 'exam_started_at'
sysreseval_exam_duration = 'exam_duration'
sysreseval_exam_mode = 'exam_mode'

initial_state_name = "initial"

self_grade_timestamp_dir = sre_pub_dir + "/last_self_grades"

svg_graph_name = "scheme.svg"

srelab_link_name = "srelab"

graphviz_default_nodesep = 0.8
graphviz_default_ranksep = 1.5
graphviz_default_splines = "curved"
graphviz_default_overlap = "prism"


class SRE:
    args = None
    module_rvlab = None
    eval_obj = None
    username = None


def datetime_to_string(dt) -> str:
    return f"{dt:%Y%m%d%H%M%S}"


def string_to_datetime(string) -> datetime:
    return datetime.strptime(string, "%Y%m%d%H%M%S")


def get_lab_name_from_cli_arg(lab_cli_arg: str, is_path: bool) -> str:
    if is_path:
        lab_cli_arg = os.path.abspath(lab_cli_arg)
    return lab_cli_arg.replace("/", "@")


def get_running_lab_name(lab_name: str, instance_start_date: datetime, username: str = None) -> str:
    if username is None:
        if SRE.username is None:
            username = ""
        else:
            username = SRE.username
    if exetests_separator in lab_name:
        raise ValueError(f"lab_name must not contain '{exetests_separator}': {lab_name!r}")
    if exetests_separator in username:
        raise ValueError(f"username must not contain '{exetests_separator}': {username!r}")
    return f"{datetime_to_string(instance_start_date)}@@@{lab_name}@@@{username}"


running_lab_name_match_pattern = '^([0-9]+)@@@(.+)@@@(.+)$'


def get_lab_name_from_running_lab_name(running_lab_name: str) -> str:
    match = re.match(running_lab_name_match_pattern, running_lab_name)
    if match:
        return match.group(2)
    else:
        return 'ERROR-running_lab_name-ILLEGAL-FORMAT'


def get_username_from_running_lab_name(running_lab_name: str) -> str:
    match = re.match(running_lab_name_match_pattern, running_lab_name)
    if match:
        return match.group(3)
    return ''


def get_abbreviated_lab_name_from_running_lab_name(running_lab_name: str) -> str:
    name = get_lab_name_from_running_lab_name(running_lab_name).replace("@", "/").rpartition("/")[2]
    return name.removesuffix(".py")


def get_current_srelab_file_from_running_lab_name(running_lab_name: str) -> str:
    lab_name = get_lab_name_from_running_lab_name(running_lab_name)
    pathstr = lab_name.replace("@", "/")
    if not pathstr.startswith("/"):
        abspath = (Path(lab_dir) / pathstr).resolve()
    else:
        abspath = Path(pathstr).resolve()
    if abspath.name.endswith(".py"):
        return str(abspath)
    else:
        return str(abspath / srelab_py_name)


def get_srelab_dir(running_lab_name: str):
    lab_name = get_lab_name_from_running_lab_name(running_lab_name)
    pathstr = lab_name.replace("@", "/")
    if not pathstr.startswith("/"):
        abspath = (Path(lab_dir) / pathstr).resolve()
    else:
        abspath = Path(pathstr).resolve()
    if abspath.name.endswith(".py"):
        return None
    else:
        return str(abspath)


def project_has_directory(running_lab_name=None) -> bool:
    if running_lab_name.endswith(".py"):
        return False
    else:
        return True


def get_archive_name(running_lab_name: str, date: datetime) -> str:
    return f"{datetime_to_string(date)}_{running_lab_name}.zst"


def private_lab_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}"


def auto_eval_log_filename(running_lab_name: str) -> str:
    return f"{private_lab_dir(running_lab_name)}/{auto_eval_log_name}"


def debug_project_marker_filename(running_lab_name: str) -> str:
    return f"{private_lab_dir(running_lab_name)}/{debug_project_marker_name}"


def link_to_user_public_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}/{user_public_dir_name}"


def public_lab_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}"


def info_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{info_json_name}"


def data_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}/{data_json_name}"


def private_mount_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}/{private_mount_dir_name}"


def files_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}/{files_dir_name}"


def records_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}/{records_dir_name}"


def srelab_link_filename(running_lab_name: str) -> str:
    return f"{private_lab_dir(running_lab_name)}/{srelab_link_name}"


def graph_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{svg_graph_name}"


def answers_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{answer_dir_name}/{answer_file_name}"


def cheat_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{answer_dir_name}/{cheat_file_name}"


def answers_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{answer_dir_name}"


def self_grade_timestamp_file(lab_name: str) -> str:
    return f"{self_grade_timestamp_dir}/{lab_name}"


