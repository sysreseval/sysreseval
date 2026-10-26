import grp
import os
import pwd
import re
import stat
from datetime import datetime
from typing import Literal

from pathlib import Path

#################################################################################
#
# Layout and site parameters
#
# Plain top-level assignments: scripts/install.sh patches them, `sre update` merges them (the
# values of the site are kept) and the site parameters file (site_params_file below) may set any
# of them.  A value of None means "the default of the installation layout", computed in the
# "Derived parameters" block below, after the site parameters file has been read.
#
#################################################################################

# "checkout": a git tree (/opt/sre, scripts/install.sh, the venv); "fhs": the Debian package
# (set by debian/rules on the installed copy: /usr/lib/sysreseval, /usr/share/sysreseval,
# /etc/sysreseval, /var/lib/sre)
install_layout = "checkout"

sre_user = "sre"
sre_uid = 1100          # None: the uid of sre_user
sre_gid = 1100          # None: the gid of sre_user
docker_group = "docker"
docker_gid = 988        # None: the gid of docker_group, else of docker_socket_path, else sre_gid

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
sre_user_public_dir = None   # None: /home/sre (checkout), sre_pub_dir/home (fhs)

lab_dir = None               # None: main_sre_dir/lab (checkout), sre_pub_dir/lab (fhs)
shipped_lab_dir = None       # None: lab_dir (checkout), /usr/share/sysreseval/lab (fhs): the labs of the package
lib_dir = None               # None: main_sre_dir/lib
graphicdir = None            # None: main_sre_dir/graphics (checkout), /usr/share/sysreseval/graphics (fhs)
fontdir = None               # None: graphicdir/fonts (checkout), /usr/share/fonts/truetype/dejavu (fhs)
translations_dirs = None     # None: [<root>/translations, main_sre_dir/translations] (checkout), [/usr/share/sysreseval/translations] (fhs)
locale_dirs = None           # None: [<root>/locale, main_sre_dir/locale] (checkout), [/usr/share/locale] (fhs)
archive_dirs = None          # None: [sre_pub_dir/archives]
sre_wrapper = None           # None: main_sre_dir/bin/sre-wrapper (checkout), /usr/bin/sre-wrapper (fhs)
sysreseval_exe = None        # None: main_sre_dir/bin/sysreseval (checkout), /usr/bin/sysreseval (fhs)
sre_exe = None               # None: main_sre_dir/sbin/sre (checkout), /usr/sbin/sre (fhs)
docker_socket_path = "/var/run/docker.sock"   # absent: no Docker daemon on this host (`sre update` skips the wipe)
self_update_allowed = None   # None: True (checkout), False (fhs: the package is updated with apt); `sre update`
network_plugin_hint = None   # None: how to install the network plugin with the switch types, by layout
kathara_hint = None          # None: how to get a Kathara with the switch modes, by layout
web_dir = None               # None: main_sre_dir/web (checkout), /usr/share/sysreseval/web (fhs): templates and static files of sre-web
web_config_file = None       # None: /etc/sreweb/web.toml (checkout), /etc/sysreseval/web.toml (fhs): configuration of sre-web
agent_config_file = None     # None: /etc/sreweb/agent.toml (checkout), /etc/sysreseval/agent.toml (fhs): configuration of sre-agent
# Site parameters file: a Python file executed into this module after the parameters above (any
# of them may be set there) and before the derived ones.  It must be owned by root (or by the
# user running the program) and not writable by the group or others.  None: /etc/sysreseval/params.py
# in the fhs layout (shipped by the Debian package), no file on a checkout.
site_params_file = None

# debug_mode:
# - allow environment variables SRE_WRAPPER and SRE_PUB_DIR to overcome the default value (insecure)
# - allow "sysreseval --debug"
debug_mode = False

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

# `sre update`: where the new versions of SRE come from (a GitHub repository) and what the
# command refreshes in lab/ (the other entries of lab/ are the site's own labs and are kept)
update_github_repository = "sysreseval/sysreseval"
update_github_api_url = "https://api.github.com"
update_tarball_url = "https://codeload.github.com/{repository}/tar.gz/{commit}"
update_default_branch = "main"       # followed by `sre update --main` (the default is the latest release)
update_http_timeout = 60             # seconds, per request
update_lab_subdirs = ["sre"]         # entries of lab/ owned by the repository, reinstalled by `sre update`

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
use_sudo_user_for_username = True

# Should projects be able to execute commands on the host (which might be useful)
# shell : execution through subprocess.run with shell=True which allow pipes
# split : execution through shlex.split to forbid pipes
# False : no execution permitted on the host
execute_commands_on_host: Literal["shell", "split", False] = "shell"


authorized_src_dir = None    # None: [lab_dir, shipped_lab_dir, '/home']

# External terminal emulator used to open machine connections.
# The command is built as: terminal_cmd_prefix[:-1] + [terminal_title_opt, title] + terminal_cmd_prefix[-1:] + [sre_wrapper, "connect", project, machine]
# The title is passed as a two-token pair (terminal_title_opt, title), so only
# terminals that accept a separate "--title TITLE"-style option work here.
# Uncomment ONE pair below (binary path may differ on your host; check with `command -v`):
#   gnome-terminal:
#     terminal_cmd_prefix = ["/usr/bin/gnome-terminal", "--"]
#     terminal_title_opt = "--title"
#   xfce4-terminal:
#     terminal_cmd_prefix = ["/usr/bin/xfce4-terminal", "-x"]
#     terminal_title_opt = "--title"
#   xterm:
#     terminal_cmd_prefix = ["/usr/bin/xterm", "-e"]
#     terminal_title_opt = "-title"
#   terminator:
#     terminal_cmd_prefix = ["/usr/bin/terminator", "-x"]
#     terminal_title_opt = "-T"
terminal_cmd_prefix = ["/usr/bin/mate-terminal", "--"]
terminal_title_opt = "--title"


#################################################################################
#
# Site parameters file
#
#################################################################################

def _load_site_params(path: str, namespace: dict) -> None:
    """Execute the site parameters file *path* into *namespace* (the globals of this module).
    The file is refused when it is not owned by root or by the current user, or when its group or
    others may write it: `sre` runs it as root.  A failure stops the program with the file name
    and the line."""
    try:
        st = os.stat(path)
        if st.st_uid not in (0, os.geteuid()):
            raise PermissionError(f"not owned by root (uid {st.st_uid})")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("writable by the group or others")
        with open(path, encoding='utf-8') as f:
            code = compile(f.read(), path, 'exec')
    except SyntaxError as e:
        raise SystemExit(f"sre: {path}:{e.lineno}: {e.msg}") from e
    except OSError as e:
        raise SystemExit(f"sre: {path}: {e}") from e
    try:
        exec(code, namespace)
    except SystemExit:
        raise
    except Exception as e:
        lineno = e.__traceback__.tb_next.tb_lineno if e.__traceback__ and e.__traceback__.tb_next else '?'
        raise SystemExit(f"sre: {path}:{lineno}: {type(e).__name__}: {e}") from e


if site_params_file is None and install_layout == "fhs":
    site_params_file = "/etc/sysreseval/params.py"
if debug_mode:
    site_params_file = os.environ.get("SRE_SITE_PARAMS", site_params_file) or None
if site_params_file and os.path.isfile(site_params_file):
    _load_site_params(site_params_file, globals())

if debug_mode:
    sre_wrapper = os.environ.get("SRE_WRAPPER", sre_wrapper)
    sre_pub_dir = os.environ.get("SRE_PUB_DIR", sre_pub_dir)


#################################################################################
#
# Derived parameters: the defaults of the installation layout for the parameters left to None
# above (an `if` block each: not parameters of their own for `sre update`)
#
#################################################################################

_fhs = install_layout == "fhs"
_root = Path(__file__).resolve().parent.parent.parent   # the checkout (<root>/src/SRE/params.py)
if _fhs:
    main_sre_dir = "/usr/lib/sysreseval"
if sre_uid is None:
    try:
        sre_uid = pwd.getpwnam(sre_user).pw_uid
    except KeyError:
        sre_uid = 1100
if sre_gid is None:
    try:
        sre_gid = pwd.getpwnam(sre_user).pw_gid
    except KeyError:
        sre_gid = 1100
if docker_gid is None:
    try:
        docker_gid = grp.getgrnam(docker_group).gr_gid
    except KeyError:
        try:
            docker_gid = os.stat(docker_socket_path).st_gid
        except OSError:
            docker_gid = sre_gid
if sre_user_public_dir is None:
    sre_user_public_dir = sre_pub_dir + "/home" if _fhs else "/home/sre"
if lab_dir is None:
    lab_dir = sre_pub_dir + "/lab" if _fhs else main_sre_dir + "/lab"
if shipped_lab_dir is None:
    shipped_lab_dir = "/usr/share/sysreseval/lab" if _fhs else lab_dir
if lib_dir is None:
    lib_dir = main_sre_dir + "/lib"
if graphicdir is None:
    graphicdir = "/usr/share/sysreseval/graphics" if _fhs else main_sre_dir + "/graphics"
if fontdir is None:
    fontdir = "/usr/share/fonts/truetype/dejavu" if _fhs else graphicdir + "/fonts"
if translations_dirs is None:
    translations_dirs = ["/usr/share/sysreseval/translations"] if _fhs \
        else [str(_root / "translations"), main_sre_dir + "/translations"]
if locale_dirs is None:
    locale_dirs = ["/usr/share/locale"] if _fhs else [str(_root / "locale"), main_sre_dir + "/locale"]
if archive_dirs is None:
    archive_dirs = [sre_pub_dir + '/archives']
if sre_wrapper is None:
    sre_wrapper = "/usr/bin/sre-wrapper" if _fhs else main_sre_dir + "/bin/sre-wrapper"
if sysreseval_exe is None:
    sysreseval_exe = "/usr/bin/sysreseval" if _fhs else main_sre_dir + "/bin/sysreseval"
if sre_exe is None:
    sre_exe = "/usr/sbin/sre" if _fhs else main_sre_dir + "/sbin/sre"
if authorized_src_dir is None:
    authorized_src_dir = list(dict.fromkeys([lab_dir, shipped_lab_dir, '/home']))
if self_update_allowed is None:
    self_update_allowed = not _fhs
if network_plugin_hint is None:
    network_plugin_hint = ("Install it with `sysreseval-network-plugin` (see the installation guide)." if _fhs
                           else f"Install it with `make network-plugin` in {main_sre_dir} (see the installation guide).")
if kathara_hint is None:
    kathara_hint = "upgrade the python3-kathara package" if _fhs else "install it again with `make venv`"
if web_dir is None:
    web_dir = "/usr/share/sysreseval/web" if _fhs else main_sre_dir + "/web"
if web_config_file is None:
    web_config_file = "/etc/sysreseval/web.toml" if _fhs else "/etc/sreweb/web.toml"
if agent_config_file is None:
    agent_config_file = "/etc/sysreseval/agent.toml" if _fhs else "/etc/sreweb/agent.toml"
del _fhs, _root


#################################################################################
#
# Don't modify parameters below
#
#################################################################################

sre_version = "0.13.2"
default_docker_image_version = "1.31"
sre_docker_namespace = "sysreseval"

def sre_docker_image(image_name: str = "base") -> str:
    return f"{sre_docker_namespace}/{image_name}:{default_docker_image_version}"

default_docker_image = sre_docker_image()

# `sre update`: state file of the installed version (commit, manifest of the installed files, pristine
# upstream values of params.py), lock and temporary directory, all in main_sre_dir
update_state_file_name = ".sre-update.json"
update_lock_file_name = ".sre-update.lock"
update_tmp_prefix = ".sre-update-"
update_params_follow_new = ("sre_version", "default_docker_image_version")  # always take the new value
update_params_backup_suffix = ".bak."   # params.py.bak.<YYYYmmdd-HHMMSS>, like scripts/install.sh
update_system_templates_dir = "scripts/etc"   # files installed by hand on every host (sudoers, .desktop...)
# keys of the state file
update_state_commit = "commit"
update_state_ref = "ref"
update_state_updated_at = "updated_at"
update_state_previous_commit = "previous_commit"
update_state_files = "files"
update_state_params_upstream = "params_upstream"

sre_projects_dir = sre_pub_dir + "/projects"

sre_name_env_variable = "SRE_LAB_NAME"
sre_xauth_cookie_env_variable = "SRE_XAUTH_COOKIE"
sre_host_ip_env_variable = "SRE_HOST_IP"
# the web agent gives `sre start` the number of the virtual X display of the project (digits);
# the x11_host machines then get SRE_DISPLAY=<sre_host_ip>:<number>, used by the images' .bashrc
# in place of <sre_host_ip>:0 (the X server of a workstation)
sre_x11_display_env_variable = "SRE_X11_DISPLAY"
sre_display_env_variable = "SRE_DISPLAY"

sre_host_ip = "172.17.0.1"

exetests_path = lib_dir + "/exetests.py"
exetests_machines_path = '/usr/local/sbin/exetests.py'
exetests_env_name = 'EXETESTS'
exetests_separator = '@@@'
default_timeout = 20
default_state_cmd_timeout = 120  # seconds, for NetScheme.cmd() / host_cmd() (0 = no timeout)

exit_code_flavor_form_needed = 3
exit_code_flavor_not_allowed = 4

default_show_nat_network = True
default_host_network_color = "deepskyblue"
default_host_network_name = "Internet"
default_host_network_shape = "hexagon"
default_host_network_exploded = False
default_host_network_edge_relative_length = 1.0

# Module-level `ipv6` lab option: None = leave Kathara's own enable_ipv6 setting (False by default),
# True/False = force IPv6 on/off in every machine; Machine(ipv6=...) overrides it per machine.
default_ipv6 = None

# Switch type of a network (`mode` of a `_network_specs` entry, Kathara collision domain mode):
# a hub sends every frame to every machine, a switch learns the MAC addresses, a managed switch
# also has VLANs and a management console.
network_mode_hub = "hub"
network_mode_switch = "switch"
network_mode_managed = "managed"
network_modes = (network_mode_hub, network_mode_switch, network_mode_managed)
default_network_mode = network_mode_hub
min_vlan_id = 1
max_vlan_id = 4094
# `@machine` in a command of NetScheme.switch_cmd() / Grade.test_switch() stands for the number of
# the switch port the machine is plugged into.
switch_port_reference_prefix = "@"
switch_cmd_error_code = -2  # exit code of a switch command that could not be run at all
# Console commands (first word of the line) a student may run on a managed switch.  Everything
# else (plugin/*, port/create, port/remove, port/epclose, debug/*, ...) is refused in user mode.
switch_user_commands = (
    "help", "showinfo",
    "port/showinfo", "port/print", "port/allprint", "port/setvlan",
    "vlan/create", "vlan/remove", "vlan/addport", "vlan/delport", "vlan/print", "vlan/allprint",
    "hash/showinfo", "hash/print", "hash/find",
    "fstp/showinfo", "fstp/print", "fstp/setfstp", "fstp/setedge", "fstp/bonus",
)
switch_console_exit_commands = ("exit", "quit", "logout")
# An open console checks this often (seconds) that its project still exists, and ends when it does not
switch_console_watch_interval = 1.0

default_machine_shape = "box"
default_network_shape = "ellipse"

pdf_schema_file = "schema.pdf"
pdf_info_file = "informations.pdf"

# Terminal appearance defaults (overridable via ~/.config/sysreseval)
terminal_font_size = 12  # font size in points
terminal_color_scheme = "black_on_white"  # "white_on_black" or "black_on_white"
content_font_size = 12  # font size in points for information/questions views
# default stylesheet of the documents drawn from lab markdown (Informations, Questions, form
# questions): Qt draws the tables without cell padding, the columns touch each other otherwise
content_style_sheet = "th, td { padding: 2px 8px; }"
default_form_field_lines = 4  # visible lines of a @@{name:+}@@ multi-line form field
system_font_size = 10  # font size in points for menus, titles, labels

# Instructor mode (`sre start --instructor-mode`, `sre set-instructor-mode`): default colours of the
# texts wrapped in instructor(); a call may override them (instructor(text, color=, background=))
instructor_text_color = "#b00020"
instructor_background_color = "#ffe3e3"
# Delimiters of an instructor fragment inside a text of info.json (private-use characters):
# <begin><color>;<background><args end><content><end>
instructor_begin_mark = "\ue000"
instructor_args_end_mark = "\ue001"
instructor_end_mark = "\ue002"

thats_all_folks_svg = graphicdir + "/Thats_all_folks.svg"
sysreseval_logo_svg = graphicdir + "/sysreseval.svg"
machine_icon_svg_file = graphicdir + "/machine.svg"
machine_forbidden_icon_svg_file = graphicdir + "/machine-forbidden.svg"
switch_icon_svg_file = graphicdir + "/switch.svg"
cloud_icon_svg_file = graphicdir + "/cloud.svg"
# the `shape` values of a network (`_network_specs`) drawn as an icon by the GUI schema and the export
# PDF when icons are on (as the default network shape otherwise) instead of a graphviz node shape
network_shape_icons = {"cloud": cloud_icon_svg_file}

# TrueType fonts embedded in the PDFs of "sre export" and "sre outline" (downloaded by "make fonts"
# into fontdir, the fonts-dejavu packages in the fhs layout): {style: file} with the styles ''
# (regular), 'B', 'I' and 'BI'. A missing style uses the regular file. If the regular file cannot
# be loaded, the core Helvetica/Courier fonts are used and the text is reduced to Latin-1.
pdf_font_files = {
    '': fontdir + "/DejaVuSans.ttf",
    'B': fontdir + "/DejaVuSans-Bold.ttf",
    'I': fontdir + "/DejaVuSans-Oblique.ttf",
    'BI': fontdir + "/DejaVuSans-BoldOblique.ttf",
}
pdf_mono_font_files = {
    '': fontdir + "/DejaVuSansMono.ttf",
    'B': fontdir + "/DejaVuSansMono-Bold.ttf",
}

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
# Keys/markers used inside data.json by Data0.to_dict()/from_dict()
data_json_ips6_key = "ips6"          # Data0.ips6 container (IPv6Interface values)
data_json_nets6_key = "nets6"        # Data0.nets6 container (IPv6Network values)
data_json_iface_marker = "__iface__" # standalone IPv4Interface / IPv6Interface field
data_json_mac_marker = "__mac__"     # standalone netaddr.EUI field
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
instructor_mode_marker_name = "instructor_mode"
# Operations log (GUI "Log" tab): every `sre state` / `sre eval` of a debug project appends what it
# executed, every `sre state` of an instructor-mode project too; lives in the public project dir,
# never written for the other projects
operations_log_name = "operations.log"
operations_log_max_output_chars = 16384  # per command output written to operations.log
operations_log_view_max_lines = 100000   # block cap of the GUI Log tab
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
group_keyword = "group"            # the student group of the owner (web front-end, when configured)

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
save_state_name = "save"
restore_state_name = "restore"
# States applied by the lab lifecycle itself (start / save / restore), never listed as user states
lifecycle_state_names = (initial_state_name, save_state_name, restore_state_name)

# --- save / restore of running projects (`sre save`, `sre restore`) ---
save_file_suffix = ".sre"
save_file_magic = b"SRESAVE1\n"
save_format_version = 1
save_stdio_arg = "-"                    # `sre restore -` reads the save file from stdin
save_tmp_dir = sre_pub_dir + "/tmp"     # not /tmp (may be a small tmpfs): full-image saves can be large
save_kathara_name = "kathara.tar"       # payload member: the Kathara save archive
save_user_public_member = "user_public" # payload member: contents of the user public dir (shared/, volumes)
# keys of the cleartext JSON header line
save_meta_format_version = "format_version"
save_meta_sre_version = "sre_version"
save_meta_running_lab_name = "running_lab_name"
save_meta_lab_name = "lab_name"
save_meta_srelab_file = "srelab_file"
save_meta_username = "username"
save_meta_saved_at = "saved_at"
save_meta_debug_project = "debug_project"
save_meta_full_images = "full_images"
save_meta_shared_path = "shared_path"
save_meta_encrypted = "encrypted"
save_meta_kdf_salt = "kdf_salt"
save_meta_kdf_iterations = "kdf_iterations"
save_kdf_iterations = 600_000
save_cipher_chunk_size = 16 * 1024 * 1024

self_grade_timestamp_dir = sre_pub_dir + "/last_self_grades"

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


def get_start_date_string_from_running_lab_name(running_lab_name: str) -> str:
    """Instance start date (YYYYmmddHHMMSS digits) encoded in a running_lab_name,
    or '' when the name does not follow get_running_lab_name().  The digits
    sort chronologically, so callers compare/sort the string and only convert
    it with string_to_datetime() for display."""
    match = re.match(running_lab_name_match_pattern, running_lab_name)
    return match.group(1) if match else ''


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


# Matches the basename produced by get_archive_name(): group 1 is the eval
# date (YYYYmmddHHMMSS), group 2 the running_lab_name (which may itself
# contain '@', '_' and '.').  Use with re.fullmatch.
archive_name_match_pattern = r'(\d{14})_(.+)\.zst'


def get_date_from_archive_name(filename: str) -> datetime | None:
    """Creation (eval) date encoded in an archive filename, or None when the
    name does not follow get_archive_name() or the digits are not a date."""
    match = re.fullmatch(archive_name_match_pattern, Path(filename).name)
    if not match:
        return None
    try:
        return string_to_datetime(match.group(1))
    except ValueError:
        return None


def private_lab_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{private_dir_name}"


def auto_eval_log_filename(running_lab_name: str) -> str:
    return f"{private_lab_dir(running_lab_name)}/{auto_eval_log_name}"


def debug_project_marker_filename(running_lab_name: str) -> str:
    return f"{private_lab_dir(running_lab_name)}/{debug_project_marker_name}"


def instructor_mode_marker_filename(running_lab_name: str) -> str:
    return f"{private_lab_dir(running_lab_name)}/{instructor_mode_marker_name}"


def operations_log_filename(running_lab_name: str) -> str:
    return f"{public_lab_dir(running_lab_name)}/{operations_log_name}"


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


def answers_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{answer_dir_name}/{answer_file_name}"


def cheat_filename(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{answer_dir_name}/{cheat_file_name}"


def answers_dir(running_lab_name: str) -> str:
    return f"{sre_projects_dir}/{running_lab_name}/{answer_dir_name}"


def self_grade_timestamp_file(lab_name: str, username: str | None = None) -> str:
    """The cooldown file of the self-evaluations of a lab: one per lab and owner (``sre eval``
    passes the owner of the project), so that the students of a shared host do not block each
    other; the old per-lab file is used when *username* is not given."""
    if username:
        return f"{self_grade_timestamp_dir}/{lab_name}@@@{username}"
    return f"{self_grade_timestamp_dir}/{lab_name}"


