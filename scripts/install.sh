#!/usr/bin/env bash
# SRE installer — interactive configuration of src/SRE/params.py, then
# venv setup and production build. Must run as root on a Linux host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PARAMS="$REPO_DIR/src/SRE/params.py"
ETC_DIR="$SCRIPT_DIR/etc"

# ── output helpers ─────────────────────────────────────────────────────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }
hr()   { printf '\n=== %s ===\n' "$*"; }

# ── prompt helpers ─────────────────────────────────────────────────────────────

# Convert space-separated integers to a Python list literal: "1 2" → "[1, 2]"
to_py_list() {
    local s="${1// /}"
    [[ -z $s ]] && { echo "[]"; return; }
    echo "[$(echo "$1" | tr -s ' ' ',')]"
}

prompt_int() {
    local label="$1" default="$2" value
    while :; do
        read -rp "$label [${default}]: " value
        value="${value:-$default}"
        [[ $value =~ ^[0-9]+$ ]] && { echo "$value"; return; }
        echo "  → '$value' is not a valid integer, try again." >&2
    done
}

prompt_int_list() {
    local label="$1" value bad
    while :; do
        read -rp "$label (space-separated, or Enter for none): " value
        bad=""
        for tok in $value; do
            [[ $tok =~ ^[0-9]+$ ]] || { bad="$tok"; break; }
        done
        [[ -z $bad ]] && { echo "$value"; return; }
        echo "  → '$bad' is not a valid integer, try again." >&2
    done
}

prompt_str() {
    local label="$1" default="$2" value
    read -rp "$label [${default}]: " value
    echo "${value:-$default}"
}

# Space-separated list of absolute paths. Enter accepts $default; "-" yields empty.
prompt_str_list() {
    local label="$1" default="$2" value bad
    while :; do
        read -rp "$label (space-separated, '-' for none) [${default}]: " value
        value="${value:-$default}"
        [[ $value == "-" ]] && { echo ""; return; }
        bad=""
        for tok in $value; do
            [[ $tok == /* ]] || { bad="$tok"; break; }
        done
        [[ -z $bad ]] && { echo "$value"; return; }
        echo "  → '$bad' is not an absolute path, try again." >&2
    done
}

# Returns Python bool literal "True" or "False"; default is "y" or "n".
prompt_bool() {
    local label="$1" default="$2" value
    while :; do
        read -rp "$label [${default}]: " value
        value="${value:-$default}"
        case "${value,,}" in
            y|yes|true)  echo "True";  return ;;
            n|no|false)  echo "False"; return ;;
        esac
        echo "  → '$value' is not yes/no, try again." >&2
    done
}

prompt_choice() {
    local label="$1" default="$2" value
    shift 2
    local choices=("$@")
    local choices_str
    choices_str=$(IFS='|'; echo "${choices[*]}")
    while :; do
        read -rp "$label (${choices_str}) [${default}]: " value
        value="${value:-$default}"
        for c in "${choices[@]}"; do
            [[ $value == "$c" ]] && { echo "$value"; return; }
        done
        echo "  → '$value' is not one of: ${choices_str}, try again." >&2
    done
}

# Returns 0 on yes, 1 on no. Default applies on Enter.
confirm() {
    local label="$1" default="${2:-N}" value
    read -rp "$label [${default}] " value || return 1
    value="${value:-$default}"
    [[ ${value,,} == y* ]]
}

# Update a "key = value" line in $PARAMS and verify the change.
# Args:
#   $1 anchor — basic-regex prefix that uniquely identifies the line (e.g. "sre_uid = ")
#   $2 line   — full replacement line
update_param() {
    local anchor="$1" replacement="$2"
    grep -qE "^${anchor}" "$PARAMS" \
        || die "params.py is missing a line matching: ^${anchor}"
    # Use | as sed delimiter; escape any | inside the replacement.
    local sed_repl="${replacement//|/\\|}"
    sed -i "s|^${anchor}.*|${sed_repl}|" "$PARAMS"
    grep -qxF "$replacement" "$PARAMS" \
        || die "Failed to apply update: $replacement"
}

# ── checks ─────────────────────────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."
[[ -f $PARAMS ]]  || die "Cannot find $PARAMS — run from a checkout of the sre repo."

# Always-present POSIX / coreutils tools — die immediately if absent.
for tool in sed grep stat getent useradd groupadd usermod install; do
    command -v "$tool" >/dev/null 2>&1 || die "Required tool not found in PATH: $tool"
done

# Executables that may be missing on a fresh host. Map: executable → Debian/Ubuntu package.
declare -A APT_PKG=(
    [docker]=docker.io
    [asciinema]=asciinema
    [make]=make
    [gcc]=gcc
    [dot]=graphviz                 # provides dot/neato/etc., used at runtime by the python `graphviz` package via .pipe()
    [python3.13]=python3.13
)

# Debian-family Python is split into multiple packages; python3.13 alone has
# no `ensurepip`, so `python3.13 -m venv` produces a venv with a broken `pip`.
# These can't be keyed by an executable in PATH (they ship stdlib modules and
# headers), so they're installed unconditionally on Debian-like hosts below.
PY_EXTRA_PKGS=(python3.13-venv python3.13-dev)

is_debian_like() {
    [[ -r /etc/os-release ]] || return 1
    local id id_like
    # shellcheck disable=SC1091
    id=$(. /etc/os-release; echo "${ID:-}")
    # shellcheck disable=SC1091
    id_like=$(. /etc/os-release; echo "${ID_LIKE:-}")
    [[ $id == debian || $id == ubuntu ]] && return 0
    [[ $id_like == *debian* ]] && return 0
    return 1
}

# True when `python3.13 -m venv` would build a working venv (ensurepip present).
py_venv_ok() {
    command -v python3.13 >/dev/null 2>&1 \
        && python3.13 -c 'import ensurepip' >/dev/null 2>&1
}

check_executables() {
    local missing=() pkgs=() tool
    for tool in "${!APT_PKG[@]}"; do
        command -v "$tool" >/dev/null 2>&1 && continue
        missing+=("$tool")
        pkgs+=("${APT_PKG[$tool]}")
    done
    # python3.13 alone produces a broken venv (no pip) on Debian-family
    # systems; pull in the extra packages whenever we're already touching apt.
    local need_py_extra=0
    if command -v python3.13 >/dev/null 2>&1 && ! py_venv_ok; then
        need_py_extra=1
        pkgs+=("${PY_EXTRA_PKGS[@]}")
    fi
    [[ ${#missing[@]} -eq 0 && $need_py_extra -eq 0 ]] && return 0

    echo
    [[ ${#missing[@]} -gt 0 ]] && warn "Missing executables: ${missing[*]}"
    [[ $need_py_extra -eq 1 ]] && warn "python3.13 is installed but lacks ensurepip — need: ${PY_EXTRA_PKGS[*]}"

    if is_debian_like && command -v apt-get >/dev/null 2>&1; then
        echo "Detected Debian/Ubuntu — the following packages would provide them:"
        printf '    %s\n' "${pkgs[@]}"
        if confirm "Install them now via apt-get?" "Y"; then
            apt-get update || warn "apt-get update failed; continuing anyway."
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" || \
                warn "apt-get install reported errors; verifying what was actually installed."
            local still=() t
            for t in "${missing[@]}"; do
                command -v "$t" >/dev/null 2>&1 || still+=("$t")
            done
            py_venv_ok || still+=("python3.13-venv")
            [[ ${#still[@]} -eq 0 ]] && return 0
            warn "Still missing after install: ${still[*]}"
            for t in "${still[@]}"; do
                case "$t" in
                    python3.13)
                        echo "  → python3.13 may not be in your distro's default repos." \
                             "On Ubuntu < 24.04 add the deadsnakes PPA; on Debian < 13 upgrade or build from source." ;;
                esac
            done
            die "Install the remaining tools manually and re-run."
        fi
    else
        echo "Not a recognised Debian/Ubuntu system — install the listed tools with your distro's package manager."
    fi
    die "Cannot continue without: ${missing[*]} ${PY_EXTRA_PKGS[*]}"
}
check_executables

DOCKER_SOCKET=/var/run/docker.sock
[[ -S $DOCKER_SOCKET ]] || die "Docker socket $DOCKER_SOCKET not found. Is the Docker daemon running? Try: systemctl start docker"

docker_gid=$(stat -c '%g' "$DOCKER_SOCKET")
echo "Detected Docker socket GID: $docker_gid"

# ── interactive prompts ────────────────────────────────────────────────────────

hr "Runtime root location"
echo "Script location: $REPO_DIR"
if [[ $REPO_DIR == "/opt/sre" ]]; then
    default_main_sre_dir="/opt/sre"
else
    echo "(install.sh is normally located at /opt/sre/scripts/install.sh)"
    default_main_sre_dir="$REPO_DIR"
fi
main_sre_dir=$(prompt_str "main_sre_dir (runtime root)" "$default_main_sre_dir")
[[ $main_sre_dir == /* ]] || die "main_sre_dir must be an absolute path."

# Shell-wrapper installs put venv/, src/, lib/, lab/ side-by-side under main_sre_dir
# and the wrappers find them via paths relative to their own location, so the repo
# being installed must already live at main_sre_dir. (A venv built at REPO_DIR and
# copied elsewhere breaks because activate scripts bake in VIRTUAL_ENV as an
# absolute path.)
if [[ $REPO_DIR != "$main_sre_dir" ]]; then
    die "REPO_DIR ($REPO_DIR) is not main_sre_dir ($main_sre_dir).
       Copy or move the repo to $main_sre_dir first, then re-run
       $main_sre_dir/scripts/install.sh."
fi

hr "SRE user configuration"
sre_uid=$(prompt_int "sre UID" 1100)
sre_gid=$(prompt_int "sre GID" 1100)

hr "Directories"
sre_pub_dir=$(prompt_str "sre_pub_dir" "/var/lib/sre")
sre_user_public_dir=$(prompt_str "sre_user_public_dir" "/home/sre")

hr "Security"
allow_privileged_machines=$(prompt_bool "allow_privileged_machines (y/n)" "y")
exec_host_raw=$(prompt_choice "execute_commands_on_host" "shell" "shell" "split" "False")
if [[ $exec_host_raw == "False" ]]; then
    exec_host_py="False"
else
    exec_host_py="\"${exec_host_raw}\""
fi

echo
echo "Extra authorized source directories for srelab.py files."
echo "The lab directory (main_sre_dir + '/lab') is always included; list any others below."
authorized_src_extra=$(prompt_str_list "extra authorized src dirs" "/home")
authorized_src_dir_py="[main_sre_dir + '/lab'"
for d in $authorized_src_extra; do
    authorized_src_dir_py+=", '$d'"
done
authorized_src_dir_py+="]"

hr "Admin access (optional)"
echo "Users/groups listed here will be treated as administrators by SRE."
admin_uids_raw=$(prompt_int_list "admin UIDs")
admin_gids_raw=$(prompt_int_list "admin GIDs")
admin_uids_py=$(to_py_list "$admin_uids_raw")
admin_gids_py=$(to_py_list "$admin_gids_raw")

hr "External terminal emulator"
echo "The GUI opens machine connections in an external terminal. Only terminals"
echo "that accept a separate '--title TITLE'-style option are supported."
# name → cmd_prefix python list ("<bin>" is replaced by the resolved path) and title option.
declare -A TERM_PREFIX=(
    [mate-terminal]='["<bin>", "--"]'
    [gnome-terminal]='["<bin>", "--"]'
    [xfce4-terminal]='["<bin>", "-x"]'
    [xterm]='["<bin>", "-e"]'
    [terminator]='["<bin>", "-x"]'
)
declare -A TERM_TITLE_OPT=(
    [mate-terminal]="--title"
    [gnome-terminal]="--title"
    [xfce4-terminal]="--title"
    [xterm]="-title"
    [terminator]="-T"
)
# Preferred order (mate-terminal first so it is the natural default).
TERM_ORDER=(mate-terminal gnome-terminal xfce4-terminal xterm terminator)
found_terms=()
declare -A TERM_BIN=()
for t in "${TERM_ORDER[@]}"; do
    if bin=$(command -v "$t" 2>/dev/null); then
        found_terms+=("$t")
        TERM_BIN[$t]="$bin"
    fi
done
chosen_term=""
terminal_cmd_prefix_py=""
terminal_title_opt_val=""
if (( ${#found_terms[@]} == 0 )); then
    warn "None of the supported terminal emulators are installed (${TERM_ORDER[*]})."
    echo "  Leaving terminal settings in params.py unchanged (default: mate-terminal)."
    echo "  Install one of them, or edit terminal_cmd_prefix / terminal_title_opt by hand."
else
    term_default="${found_terms[0]}"
    for t in "${found_terms[@]}"; do
        [[ $t == mate-terminal ]] && { term_default="mate-terminal"; break; }
    done
    chosen_term=$(prompt_choice "Which terminal emulator should the GUI use?" "$term_default" "${found_terms[@]}")
    terminal_cmd_prefix_py="${TERM_PREFIX[$chosen_term]/<bin>/${TERM_BIN[$chosen_term]}}"
    terminal_title_opt_val="${TERM_TITLE_OPT[$chosen_term]}"
fi

# ── summary ────────────────────────────────────────────────────────────────────

hr "Configuration summary"
printf '  %-28s = %s\n' \
    main_sre_dir                "$main_sre_dir"                \
    sre_uid                     "$sre_uid"                     \
    sre_gid                     "$sre_gid"                     \
    docker_gid                  "$docker_gid"                  \
    sre_pub_dir                 "$sre_pub_dir"                 \
    sre_user_public_dir         "$sre_user_public_dir"         \
    allow_privileged_machines   "$allow_privileged_machines"   \
    execute_commands_on_host    "$exec_host_py"                \
    authorized_src_dir          "$authorized_src_dir_py"       \
    admin_uids                  "$admin_uids_py"               \
    admin_gids                  "$admin_gids_py"                \
    terminal_emulator           "${chosen_term:-(unchanged)}"
echo
confirm "Proceed with these settings?" "N" || { echo "Aborted."; exit 0; }

# ── patch params.py ────────────────────────────────────────────────────────────

backup="$PARAMS.bak.$(date +%Y%m%d-%H%M%S)"
cp -p "$PARAMS" "$backup"
echo "Saved backup → $backup"

echo "Patching $PARAMS …"
update_param 'main_sre_dir = '              "main_sre_dir = \"${main_sre_dir}\""
update_param 'sre_uid = '                   "sre_uid = ${sre_uid}"
update_param 'sre_gid = '                   "sre_gid = ${sre_gid}"
update_param 'docker_gid = '                "docker_gid = ${docker_gid}"
update_param 'sre_pub_dir = '               "sre_pub_dir = \"${sre_pub_dir}\""
update_param 'sre_user_public_dir = '       "sre_user_public_dir = \"${sre_user_public_dir}\""
update_param 'allow_privileged_machines = ' "allow_privileged_machines = ${allow_privileged_machines}"
update_param 'execute_commands_on_host:'    "execute_commands_on_host: Literal[\"shell\", \"split\", False] = ${exec_host_py}"
update_param 'authorized_src_dir = '        "authorized_src_dir = ${authorized_src_dir_py}"
update_param 'admin_uids = '                "admin_uids = ${admin_uids_py}"
update_param 'admin_gids = '                "admin_gids = ${admin_gids_py}"
if [[ -n $chosen_term ]]; then
    update_param 'terminal_cmd_prefix = ' "terminal_cmd_prefix = ${terminal_cmd_prefix_py}"
    update_param 'terminal_title_opt = '  "terminal_title_opt = \"${terminal_title_opt_val}\""
fi
echo "Done."

# `make install` refuses while debug_mode = True.
if grep -qE '^debug_mode[[:space:]]*=[[:space:]]*True' "$PARAMS"; then
    echo "Disabling debug_mode (required for production install) …"
    (cd "$REPO_DIR" && make remove-debug-mode)
fi

# ── create sre user and group ──────────────────────────────────────────────────

hr "User and group setup"

ensure_group() {
    local name="$1" gid="$2"
    if getent group "$name" >/dev/null; then
        local existing
        existing=$(getent group "$name" | cut -d: -f3)
        if [[ $existing == "$gid" ]]; then
            echo "Group '$name' (GID $gid) already exists — OK."
        else
            warn "Group '$name' exists with GID $existing (you asked $gid). Keeping existing."
        fi
    elif getent group "$gid" >/dev/null; then
        warn "GID $gid already in use by '$(getent group "$gid" | cut -d: -f1)'. Skipping group creation."
    else
        groupadd -g "$gid" "$name"
        echo "Created group '$name' (GID $gid)."
    fi
}

ensure_user() {
    local name="$1" uid="$2" gid="$3" home="$4"
    if getent passwd "$name" >/dev/null; then
        local existing
        existing=$(getent passwd "$name" | cut -d: -f3)
        if [[ $existing == "$uid" ]]; then
            echo "User '$name' (UID $uid) already exists — OK."
        else
            warn "User '$name' exists with UID $existing (you asked $uid). Keeping existing."
        fi
    elif getent passwd "$uid" >/dev/null; then
        warn "UID $uid already in use by '$(getent passwd "$uid" | cut -d: -f1)'. Skipping user creation."
    else
        useradd -u "$uid" -g "$gid" -r -s /usr/sbin/nologin -d "$home" "$name"
        echo "Created user '$name' (UID $uid)."
    fi
}

ensure_group sre "$sre_gid"
ensure_user  sre "$sre_uid" "$sre_gid" /home/sre

# Reset the install tree to root:root first, then hand specific subdirs over to
# the sre user below. Without this, files checked in / extracted with stale
# 1100:1100 ownership keep that uid even when the admin picks a different sre
# uid — which leaves dirs that nobody on the host actually owns.
chown -R root:root "$main_sre_dir"

mkdir -p "$sre_user_public_dir" "$sre_pub_dir"
chown -R sre:sre "$sre_user_public_dir" "$sre_pub_dir"
chmod 755 "$sre_user_public_dir"

# Make the install tree world-readable. sysreseval runs as the logged-in
# student (not as the sre user) and imports modules from src/ during
# startup — so any path component without o+r/o+x breaks the GUI for
# everyone but root. `X` adds execute only to dirs and already-executable
# files; `go-w` strips group/other write for safety. The privileged
# subtrees (lab/, lib/) are tightened immediately below; runtime state
# under $sre_pub_dir is permission-restricted separately.
chmod -R a+rX,go-w "$main_sre_dir"

# Hand lab/ and lib/ to the sre user and strip world access. lab/ holds
# srelab.py grading logic and lib/ holds helper modules loaded inside
# srelab.py after sre drops privileges — neither should be readable by
# students. Mode 0750 on dirs, 0640 on files: sre owner has full access,
# sre group reads, other has nothing. Runs after the world-readable pass
# above so it overrides those bits on these two subtrees only.
for d in lab lib; do
    [[ -d $main_sre_dir/$d ]] || continue
    chown -R sre:sre "$main_sre_dir/$d"
    chmod -R u=rwX,g=rX,o= "$main_sre_dir/$d"
done

# Add sre to docker group (membership by GID).
docker_group=$(getent group "$docker_gid" | cut -d: -f1 || true)
if [[ -n $docker_group ]]; then
    echo "Adding sre to Docker group '$docker_group' …"
    usermod -aG "$docker_group" sre
else
    warn "No group found for Docker GID $docker_gid; skipping usermod."
fi

# ── optional system files ─────────────────────────────────────────────────────

# Copy a template to a system location, substituting /opt/sre with $main_sre_dir.
# The templates under scripts/etc/ keep /opt/sre as a placeholder so they remain
# valid as standalone files (manual installs into /opt/sre work without any sed).
install_templated() {
    local src="$1" dst="$2" mode="$3"
    sed "s|/opt/sre|${main_sre_dir}|g" "$src" \
        | install -m "$mode" -o root -g root /dev/stdin "$dst"
}

hr "Optional system files"

if [[ -f $ETC_DIR/sudoers.d-sre ]]; then
    echo "The sudoers rule is required: sysreseval invokes 'sudo ${main_sre_dir}/sbin/sre --user'"
    echo "through sre-wrapper, so without it the GUI cannot start labs."
    if confirm "Install $ETC_DIR/sudoers.d-sre to /etc/sudoers.d/sre?" "Y"; then
        install_templated "$ETC_DIR/sudoers.d-sre" /etc/sudoers.d/sre 0440
        if visudo -c -f /etc/sudoers.d/sre >/dev/null; then
            echo "Installed /etc/sudoers.d/sre."
        else
            rm -f /etc/sudoers.d/sre
            die "sudoers file failed visudo validation; not installed."
        fi
    else
        warn "Skipping sudoers install — sysreseval will not be able to start labs until you install it manually."
    fi
fi

if [[ -f $ETC_DIR/sysreseval.desktop ]]; then
    if confirm "Install $ETC_DIR/sysreseval.desktop to /usr/share/applications/?" "Y"; then
        install_templated "$ETC_DIR/sysreseval.desktop" /usr/share/applications/sysreseval.desktop 0644
        echo "Installed /usr/share/applications/sysreseval.desktop."
    fi
fi

if [[ -f $ETC_DIR/sre_bash_completion ]]; then
    if confirm "Install $ETC_DIR/sre_bash_completion to /etc/bash_completion.d/sre?" "Y"; then
        install -m 0644 -o root -g root "$ETC_DIR/sre_bash_completion" /etc/bash_completion.d/sre
        echo "Installed /etc/bash_completion.d/sre."
    fi
fi

if [[ -f $ETC_DIR/sre-preload-images.service ]] && command -v systemctl >/dev/null 2>&1; then
    if confirm "Install systemd unit sre-preload-images.service?" "N"; then
        # systemd derives mount-unit names by escaping the mount point path: strip the
        # leading "/", replace remaining "/" with "-", append ".mount".
        mount_unit_name="$(echo "${main_sre_dir#/}" | tr '/' '-').mount"
        sed -e "s|/opt/sre|${main_sre_dir}|g" -e "s|opt-sre\.mount|${mount_unit_name}|g" \
            "$ETC_DIR/sre-preload-images.service" \
            | install -m 0644 -o root -g root /dev/stdin /etc/systemd/system/sre-preload-images.service
        systemctl daemon-reload
        echo "Installed sre-preload-images.service (not enabled)."
        echo "  → enable with: systemctl enable --now sre-preload-images.service"
        echo "  → note: the unit requires ${mount_unit_name} (the systemd mount unit for ${main_sre_dir})."
    fi
fi

# ── build and install ──────────────────────────────────────────────────────────

cd "$REPO_DIR"

hr "Running make venv"
make venv

hr "Running make install"
make install

# ── symlinks in /usr/local/{bin,sbin} ──────────────────────────────────────────

hr "Optional symlinks in /usr/local/{bin,sbin}"
echo "Adds symlinks so 'sre', 'sysreseval', and 'sre-wrapper' can be launched"
echo "without their full path (alternative to adding ${main_sre_dir}/bin and"
echo "${main_sre_dir}/sbin to the system-wide PATH)."

bin_files=()
sbin_files=()
[[ -d $REPO_DIR/bin  ]] && while IFS= read -r f; do bin_files+=("$f");  done < <(find "$REPO_DIR/bin"  -maxdepth 1 -type f -executable -printf '%f\n')
[[ -d $REPO_DIR/sbin ]] && while IFS= read -r f; do sbin_files+=("$f"); done < <(find "$REPO_DIR/sbin" -maxdepth 1 -type f -executable -printf '%f\n')

install_symlink() {
    local src="$1" dst="$2"
    if [[ -e $dst && ! -L $dst ]]; then
        warn "Skipping $dst — not a symlink, refusing to overwrite."
        return
    fi
    ln -sfn "$src" "$dst"
    echo "  $dst → $src"
}

if (( ${#bin_files[@]} + ${#sbin_files[@]} == 0 )); then
    warn "No executables found under $REPO_DIR/bin or $REPO_DIR/sbin; skipping symlinks."
elif confirm "Create symlinks in /usr/local/bin and /usr/local/sbin?" "Y"; then
    install -d -m 0755 /usr/local/bin /usr/local/sbin
    for f in "${bin_files[@]}";  do install_symlink "${main_sre_dir}/bin/$f"  "/usr/local/bin/$f";  done
    for f in "${sbin_files[@]}"; do install_symlink "${main_sre_dir}/sbin/$f" "/usr/local/sbin/$f"; done
fi

# ── done ───────────────────────────────────────────────────────────────────────

hr "Installation complete"
cat <<EOF
Built artifacts:
  $main_sre_dir/sbin/sre          (shell wrapper → venv python + src/sre.py)
  $main_sre_dir/bin/sysreseval    (shell wrapper → venv python + src/sysreseval.py)
  $main_sre_dir/bin/sre-wrapper   (compiled C sudo wrapper)

Backup of params.py: $backup

Next steps (manual):
EOF
echo "  - Verify Docker access for the sre user: 'sudo -u sre docker ps'."

# ── X11 access for lab virtual machines ─────────────────────────────────────────

# Lab containers run graphical (X11) apps that display on the host's X server,
# which must accept TCP connections on port 6000 (display :0). Modern X servers
# ship with '-nolisten tcp', so this is off until an admin enables it. Purely
# informational — never alters the exit status (the installer may run headless).
hr "X11 access for lab virtual machines"
if command -v ss >/dev/null 2>&1; then
    x_listening=$(ss -ltn 2>/dev/null)
elif command -v netstat >/dev/null 2>&1; then
    x_listening=$(netstat -ltn 2>/dev/null)
else
    x_listening=""
    echo "Neither 'ss' nor 'netstat' is available — skipping the X server TCP check."
fi
if [[ -n $x_listening ]]; then
    if grep -qE ':6000[[:space:]]' <<<"$x_listening"; then
        echo "X server is listening on TCP port 6000 — X11 apps in lab virtual machines can reach it."
    else
        warn "No X server is listening on TCP port 6000."
        echo "  To run graphical (X11) applications inside the lab virtual machines, the host's"
        echo "  X server must accept TCP connections on port 6000 (disabled by default via"
        echo "  '-nolisten tcp'). See 'Post-install steps' in docs/sphinx/installation.md for"
        echo "  how to enable it for your display manager."
    fi
fi
