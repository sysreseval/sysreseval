# /etc/sysreseval/params.py: site parameters of SysResEval (the Debian package).
#
# Python syntax.  This file is executed by /usr/lib/sysreseval/SRE/params.py after its own
# parameters and before the values derived from them, so any parameter of that file may be set
# here under the same name; a parameter left unset keeps the default of the package layout.
# It is read by `sre` (as root, through sudo) and by the sysreseval GUI (as the student): keep it
# owned by root, mode 0644.  A syntax error stops every command.
#
# Defaults of the package layout (set a line only to change it):
#
# sre_pub_dir = "/var/lib/sre"                # projects, archives, exam.json, the labs (lab/)
# sre_user_public_dir = "/var/lib/sre/home"   # the directories shared with the machines (/shared)
# lab_dir = "/var/lib/sre/lab"                # the labs: lab/sre -> /usr/share/sysreseval/lab/sre, plus the site's
# authorized_src_dir = ["/var/lib/sre/lab", "/usr/share/sysreseval/lab", "/home"]   # where a lab file may be
# archive_dirs = ["/var/lib/sre/archives"]    # where the evaluation archives are written
# admin_uids = []                             # users allowed to run the archive tools (cat, sheet, outline, watch...)
# admin_gids = [2000]                         # groups allowed to run them
# allow_privileged_machines = True
# check_project_owner = True                 # user mode: own projects and root's only (False: every project)
# execute_commands_on_host = "shell"          # "shell", "split" or False
# terminal_cmd_prefix = ["/usr/bin/mate-terminal", "--"]   # external terminal of the GUI (the choices are in params.py)
# terminal_title_opt = "--title"
# debug_mode = False
