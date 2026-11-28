#!/bin/bash
# Prepare this host for the Podman engine of SRE (container_engine = "podman", or an entry of
# container_engine_by_host, in params.py).  Run once as root; running it again changes nothing.
#
# The machines of a project are then rootless Podman containers of the account sre_user:
#   - the account gets a range of subordinate uids and gids (/etc/subuid, /etc/subgid), large
#     enough for podman_uid_ranges projects, each in a range of its own;
#   - its systemd user manager is started at boot (loginctl enable-linger): the hubs of
#     the networks are its units, and it makes the user namespace of Podman after each boot;
#   - that user manager gets every resource controller for its machines (a drop-in of
#     user@<uid>.service: cpu cpuset io memory pids, where systemd gives cpu memory pids): a
#     Kubernetes node asks for cpuset.  It applies when the user manager starts: at once when
#     no project runs, else at the next boot;
#   - the directory podman_dir gets the configuration and the image store of the engine;
#   - the user namespace of the account is created, and Podman is asked to answer both as the
#     account and with the group the sre command runs with (docker_gid);
#   - the quota of kernel keys of a user is raised (a file of sysctl.d): the services of a
#     machine running systemd each use one;
#   - the services of SRE installed on the host (the web agent, the wipe at shutdown, the preload
#     of the images) are ordered after that user manager, by a drop-in each
#     (/etc/systemd/system/<unit>.d/10-sre-podman.conf): at a shutdown they stop, evaluate and
#     wipe the projects while the machines still run, where their unit files only know Docker;
#   - on a host without Docker, the address the machines reach the host at (sre_host_ip, the one
#     of the bridge of Docker) is given to an interface of its own by a unit started at boot
#     (sre-host-address.service).  With Docker installed the unit is removed: the bridge has it
#     (PODMAN_HOST_ADDRESS=yes: the unit all the same, for a Docker that does not use that
#     address; no: never, the administrator gives the host the address);
#   - on a host with the AppArmor profile of tcpdump (the package tcpdump of Debian and Ubuntu),
#     the site file of that profile (/etc/apparmor.d/local/usr.bin.tcpdump) gets two lines: a
#     tcpdump run in a machine is under that profile, which takes signals from unconfined
#     processes only, and those of a machine carry the label of the container runtime; without
#     the lines nothing in a machine ends a tcpdump (timeout, kill).  A site file that already
#     names a line, even commented out, keeps it as it is.
# It also says what the engine would refuse on this host: a lab with a switch without the switch
# program, a machine with an outside interface without pasta or without the host address.
#
# The values come from params.py of this installation; each can be given in the environment
# instead: PODMAN_USER, PODMAN_DIR, PODMAN_UID_RANGES, and PODMAN_SUBID_FIRST (the first
# subordinate id, when the account has no range yet: 20000000, or above the ranges already given
# to other accounts), PODMAN_ORDERED_UNITS (the services to order, separated by spaces; empty:
# none).  A registry mirror is the matter of the administrator:
# <podman_dir>/config/containers/registries.conf.
#
# `make podman-setup` runs it from a checkout; the Debian package sysreseval-podman installs it
# as /usr/sbin/sysreseval-podman-setup and runs it when it is installed.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RANGE_SIZE=65536
CONTROLLERS="cpu cpuset io memory pids"
ADDRESS_INTERFACE=sre-host
ADDRESS_UNIT=sre-host-address.service
APPARMOR_DIR=/etc/apparmor.d
APPARMOR_ENABLED=/sys/module/apparmor/parameters/enabled
# the AppArmor labels the processes of a machine carry: the profile of the container runtime
MACHINE_LABELS="crun runc"

case "${1:-}" in
    -h|--help)
        sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
        echo "usage: $(basename "$0")"
        exit 0;;
esac

fail() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

# ---- the layout of the installation -----------------------------------------------------
# a checkout (this script in <root>/scripts), or the Debian packages (in /usr/sbin)
if [ -f "$ROOT/src/SRE/params.py" ]; then
    SRC="$ROOT/src"
    PYTHON="$ROOT/venv/bin/python"
    [ -x "$PYTHON" ] || PYTHON=python3
    keys_source="$ROOT/scripts/etc/sre-podman.conf"
    keys_conf=/etc/sysctl.d/60-sre-podman.conf
    params_file="$SRC/SRE/params.py"
else
    SRC="${SRE_PACKAGE_DIR:-/usr/lib/sysreseval}"
    [ -f "$SRC/SRE/params.py" ] || fail "no params.py of SRE found ($ROOT/src/SRE, $SRC/SRE)"
    PYTHON=python3
    keys_source=
    keys_conf=/usr/lib/sysctl.d/60-sysreseval-podman.conf       # a file of the package
    params_file=/etc/sysreseval/params.py
fi

[ "$(id -u)" = 0 ] || fail "run this script as root"
# before anything is changed: the engine lives in the systemd user manager of the account
[ -d /run/systemd/system ] || fail "systemd is not running here (a container, the build of an image): run this script once the host has booted"

param() {
    "$PYTHON" -W ignore -c 'import sys; sys.path.insert(0, sys.argv[1]); from SRE import params; print(getattr(params, sys.argv[2]))' \
        "$SRC" "$1" || fail "cannot read $1 in $SRC/SRE/params.py"
}
: "${PODMAN_USER:=$(param sre_user)}"
: "${PODMAN_DIR:=$(param podman_dir)}"
: "${PODMAN_UID_RANGES:=$(param podman_uid_ranges)}"
user="$PODMAN_USER"; dir="$PODMAN_DIR"
ranges="$PODMAN_UID_RANGES"; [ "$ranges" -ge 1 ] 2>/dev/null || ranges=1
cli_gid="$(param docker_gid)"       # the group the sre command runs with once it has dropped root

# ---- what must be installed -------------------------------------------------------------
missing=""
for program in podman newuidmap newgidmap vde_plug nsenter setpriv systemd-run loginctl ip tar; do
    command -v "$program" >/dev/null 2>&1 || missing="$missing $program"
done
[ -z "$missing" ] || fail "not installed:$missing (Debian packages: podman uidmap vdeplug util-linux iproute2 systemd)"

uid="$(id -u "$user" 2>/dev/null)" || fail "no account $user on this host"
gid="$(id -g "$user")"              # its primary group: the only one newuidmap makes a user namespace for
getent group "$cli_gid" >/dev/null || fail "no group with the gid $cli_gid (docker_gid of params.py)"

# ---- subordinate uids and gids ----------------------------------------------------------
needed=$((ranges * RANGE_SIZE))
range_of() { awk -F: -v u="$user" '$1 == u { print $2, $3; exit }' "$1" 2>/dev/null; }
highest_end() { cat /etc/subuid /etc/subgid 2>/dev/null | awk -F: '$2 + $3 > m { m = $2 + $3 } END { print m + 0 }'; }
if [ -z "$(range_of /etc/subuid)" ] && [ -z "$(range_of /etc/subgid)" ]; then
    first="${PODMAN_SUBID_FIRST:-20000000}"
    end="$(highest_end)"
    [ "$first" -ge "$end" ] || first=$(( (end / RANGE_SIZE + 1) * RANGE_SIZE ))
    count=$(( (ranges + 1) * RANGE_SIZE ))      # one range to spare for a container without a range of its own
    last=$((first + count - 1))
    for id in "$first" "$last"; do
        ! getent passwd "$id" >/dev/null || fail "the uid $id is an account of this host: choose another PODMAN_SUBID_FIRST"
    done
    usermod --add-subuids "$first-$last" --add-subgids "$first-$last" "$user"
    echo "subordinate ids of $user: $first-$last"
else
    for file in /etc/subuid /etc/subgid; do
        set -- $(range_of "$file")
        [ -n "${2:-}" ] || fail "$user has a range in /etc/subuid or /etc/subgid but none in $file"
        [ "$2" -ge "$needed" ] || fail "the range of $user in $file has $2 ids: $needed are needed for podman_uid_ranges = $ranges"
    done
fi

# ---- the user manager of the account ----------------------------------------------------
# write_if_changed FILE LINE...: true when the file was written
write_if_changed() {
    local file="$1" wanted; shift
    wanted="$(printf '%s\n' "$@")"
    [ "$(cat "$file" 2>/dev/null)" != "$wanted" ] || return 1
    install -d -m 0755 "$(dirname "$file")"
    printf '%s\n' "$wanted" > "$file"
    chmod 0644 "$file"
    echo "written: $file"
}
# before its first start: the controllers its machines may use
if write_if_changed "/etc/systemd/system/user@$uid.service.d/10-sre-podman.conf" \
        "# written by $(basename "$0") of SRE: the machines of the Podman engine get every controller" \
        '[Service]' "Delegate=$CONTROLLERS"; then
    systemctl daemon-reload
fi
runtime="/run/user/$uid"
wait_for_the_manager() {
    for _ in $(seq 60); do [ -S "$runtime/bus" ] && return 0; sleep 0.5; done
    fail "the user manager of $user did not start (no $runtime/bus)"
}
loginctl enable-linger "$user"
wait_for_the_manager

# ---- the directory of the engine --------------------------------------------------------
install -d -m 700 -o "$uid" -g "$gid" "$dir"
case "$(stat -f -c %T "$dir")" in
    nfs*|cifs|smb*|fuse.sshfs) fail "$dir is on a network filesystem: podman_dir must be a local disk";;
esac
install -d -m 700 -o "$uid" -g "$gid" "$dir/config" "$dir/config/containers" "$dir/data"
conf="$dir/config/containers/containers.conf"
if [ ! -e "$conf" ]; then
    # keyring: a machine with systemd would use up the key quota of the account;
    # exit_command_delay: the helpers of a finished exec leave at once (300 s by default)
    printf '%s\n' "# written by $(basename "$0") of SRE" '[containers]' 'keyring = false' '' \
        '[engine]' 'exit_command_delay = 1' > "$conf"
    chown "$uid:$gid" "$conf"; chmod 644 "$conf"
    echo "written: $conf"
fi

with_group() {      # with_group GID command...: the command as the account, with that group and no other
    local group="$1"; shift
    ( cd "$dir" && setpriv --reuid "$uid" --regid "$group" --clear-groups \
        env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 \
            HOME="$dir" USER="$user" LOGNAME="$user" XDG_RUNTIME_DIR="$runtime" \
            XDG_CONFIG_HOME="$dir/config" XDG_DATA_HOME="$dir/data" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" "$@" )
}

# ---- the controllers of a user manager that was already running --------------------------
# It reads its unit when it starts.  Restarting it ends everything it runs: only done when it
# runs nothing of SRE (no network, no machine).
manager_cgroup="/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service"
has_controllers() {
    local given; given=" $(cat "$manager_cgroup/cgroup.controllers" 2>/dev/null) "
    for controller in $CONTROLLERS; do
        case "$given" in *" $controller "*) ;; *) return 1;; esac
    done
}
if [ -d "$manager_cgroup" ] && ! has_controllers; then
    running="$(with_group "$gid" systemctl --user list-units --plain --no-legend 'srelab-*' 'libpod-*' 2>/dev/null | grep -c . || true)"
    if [ "$running" = 0 ]; then
        systemctl restart "user@$uid.service"
        wait_for_the_manager
        if has_controllers; then
            echo "user manager of $user restarted: its machines get $CONTROLLERS"
        else
            note "the user manager of $user has the controllers $(cat "$manager_cgroup/cgroup.controllers" 2>/dev/null) only ($CONTROLLERS asked): a Kubernetes node will not start in a machine."
        fi
    else
        note "projects run on this host: their machines keep the controllers $(cat "$manager_cgroup/cgroup.controllers") until the user manager of $user starts again (the next boot); a Kubernetes node needs cpuset."
    fi
fi

# ---- the user namespace of the account --------------------------------------------------
mapped_ids() { with_group "$gid" podman unshare cat /proc/self/uid_map 2>/dev/null | awk '$1 != 0 { n += $3 } END { print n + 0 }'; }
if [ "$(mapped_ids)" -lt "$needed" ]; then
    # a namespace made before the range was given (or enlarged): made again
    with_group "$gid" podman system migrate >/dev/null 2>&1 || true
fi
[ "$(mapped_ids)" -ge "$needed" ] || fail "the user namespace of $user maps $(mapped_ids) subordinate uids: $needed are needed (podman unshare cat /proc/self/uid_map)"
# what the sre command does: it joins that namespace with its own group, and starts units
with_group "$cli_gid" podman info --format 'podman {{.Version.Version}}, {{.Host.OCIRuntime.Name}}, images in {{.Store.GraphRoot}} ({{.Store.GraphDriverName}})' \
    || fail "podman does not answer as $user with the group $cli_gid"
with_group "$cli_gid" systemd-run --user --collect --wait --quiet true || fail "the user manager of $user does not run a unit"

# ---- the key quota of a project ---------------------------------------------------------
if [ "$(sysctl -n kernel.keys.maxkeys)" -lt 20000 ] || [ "$(sysctl -n kernel.keys.maxbytes)" -lt 2000000 ]; then
    if [ -n "$keys_source" ]; then
        install -m 0644 -o root -g root "$keys_source" "$keys_conf"
        echo "written: $keys_conf"
    fi
    [ -f "$keys_conf" ] || fail "no $keys_conf (a file of the package sysreseval-podman)"
    sysctl -q -p "$keys_conf"
    echo "kernel.keys.maxkeys = $(sysctl -n kernel.keys.maxkeys)"
fi

# ---- the order of the services of SRE ---------------------------------------------------
# A unit ordered after the user manager is stopped before it: the machines, their networks and
# the namespace of Podman are there until the services that act on the projects are done.
ordered_units=${PODMAN_ORDERED_UNITS-sre-agent.service sysreseval-agent.service sre-wipe-at-shutdown.service sre-preload-images.service sysreseval-preload-images.service}
reload=
for unit in $ordered_units; do
    systemctl cat "$unit" >/dev/null 2>&1 || continue       # not installed on this host
    if write_if_changed "/etc/systemd/system/$unit.d/10-sre-podman.conf" \
            "# written by $(basename "$0") of SRE: the Podman engine runs in the user manager of $user" \
            '[Unit]' "Wants=user@$uid.service" "After=user@$uid.service"; then
        reload=1
    fi
done
[ -z "$reload" ] || systemctl daemon-reload

# ---- the address of the host ------------------------------------------------------------
# A machine with an outside interface reaches the host at sre_host_ip (its X server, the X
# desktops of the web agent, the services of the labs' gateways).  Where Docker runs, its bridge
# has that address.  Without Docker an interface of SRE carries it, alone (a /32: no route).
host_ip="$(param sre_host_ip)"
address_unit="/etc/systemd/system/$ADDRESS_UNIT"
docker_installed() { command -v dockerd >/dev/null 2>&1 || systemctl cat docker.service >/dev/null 2>&1; }
on_another_interface() { ip -4 -o addr show | awk -v a="$host_ip/" -v own="$ADDRESS_INTERFACE" '$2 != own && index($4, a) == 1 { found = 1 } END { exit !found }'; }
case "${PODMAN_HOST_ADDRESS:=auto}" in
    auto) if docker_installed; then address=no; else address=yes; fi;;
    yes|no) address="$PODMAN_HOST_ADDRESS";;
    *) fail "PODMAN_HOST_ADDRESS=$PODMAN_HOST_ADDRESS: auto, yes or no";;
esac
if [ "$address" = no ]; then
    if [ -e "$address_unit" ]; then
        systemctl disable --now "$ADDRESS_UNIT" >/dev/null 2>&1 || true
        rm -f "$address_unit"
        systemctl daemon-reload
        echo "removed: $address_unit"
    fi
elif [ -e "$address_unit" ] || ! on_another_interface; then
    # After Docker, when there is one: the unit does nothing where another interface has the
    # address by then (a Docker installed after this script was run).
    if write_if_changed "$address_unit" \
            "# written by $(basename "$0") of SRE: the address the machines of a project reach the host at" \
            "# (sre_host_ip of params.py), on a host where the bridge of Docker does not have it" \
            '[Unit]' \
            'Description=Address of the host for the machines of SysResEval (Podman engine)' \
            'After=docker.service' \
            'Before=sre-agent.service sysreseval-agent.service' \
            '' \
            '[Service]' \
            'Type=oneshot' \
            'RemainAfterExit=yes' \
            "ExecStart=/bin/sh -c 'if ip -4 -o addr show | grep -v \" $ADDRESS_INTERFACE \" | grep -q \" $host_ip/\"; then exit 0; fi; ip link show $ADDRESS_INTERFACE >/dev/null 2>&1 || ip link add $ADDRESS_INTERFACE type dummy; ip addr replace $host_ip/32 dev $ADDRESS_INTERFACE && ip link set $ADDRESS_INTERFACE up'" \
            "ExecStop=-/bin/sh -c 'ip link delete $ADDRESS_INTERFACE'" \
            '' \
            '[Install]' \
            'WantedBy=multi-user.target'; then
        systemctl daemon-reload
        systemctl enable "$ADDRESS_UNIT" >/dev/null 2>&1
        systemctl restart "$ADDRESS_UNIT" || fail "$ADDRESS_UNIT did not start (systemctl status $ADDRESS_UNIT)"
    elif ! systemctl is-active --quiet "$ADDRESS_UNIT"; then
        systemctl enable "$ADDRESS_UNIT" >/dev/null 2>&1
        systemctl start "$ADDRESS_UNIT" || fail "$ADDRESS_UNIT did not start (systemctl status $ADDRESS_UNIT)"
    fi
fi

# ---- AppArmor: a tcpdump run in a machine -----------------------------------------------
# A program of a machine whose path has a profile on the host runs under that profile.  The
# one of tcpdump takes signals from "unconfined" processes only, and the processes of a machine
# carry the label of the container runtime: `timeout 5 tcpdump` never ends there, `kill` does
# nothing (Ctrl-C in a terminal works: that signal comes from the kernel).  The site file of
# the profile gets a line per label; one it already names, even commented out, is left alone.
tcpdump_signals() {
    local profile="$APPARMOR_DIR/usr.bin.tcpdump" site="$APPARMOR_DIR/local/usr.bin.tcpdump" label rule added=
    [ -f "$profile" ] || return 0
    grep -q '<local/usr.bin.tcpdump>' "$profile" || return 0        # a profile without a site file
    for label in $MACHINE_LABELS; do
        rule="signal (receive) peer=$label,"
        ! grep -qsF "$rule" "$site" || continue
        if [ -z "$added" ]; then
            install -d -m 0755 "$(dirname "$site")"
            echo "# written by $(basename "$0") of SRE: a machine of the Podman engine may end its tcpdump (timeout, kill)" >> "$site"
            added=1
        fi
        echo "$rule" >> "$site"
    done
    [ -n "$added" ] || return 0
    echo "written: $site"
    # loaded again where AppArmor is on and the profile in use
    if [ "$(cat "$APPARMOR_ENABLED" 2>/dev/null)" = Y ] && [ ! -e "$APPARMOR_DIR/disable/usr.bin.tcpdump" ] \
            && command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -r "$profile" || note "the AppArmor profile of tcpdump was not loaded again (apparmor_parser -r $profile): a tcpdump run in a machine cannot be ended there until it is."
    fi
}
tcpdump_signals

# ---- what a lab may need on top ---------------------------------------------------------
switch="$(param vde_switch_program)"
[ -x "$switch" ] || note "no switch program ($switch): a lab with a 'switch' or 'managed' network is refused; $(param vde_switch_hint)."
command -v pasta >/dev/null 2>&1 || note "pasta is not installed (Debian package passt): a lab with an outside interface ('bridged') is refused."
ip -4 -o addr show | grep -q " $host_ip/" || note "no interface of this host has $host_ip (sre_host_ip; the bridge of Docker has it once Docker runs): a lab with an outside interface is refused."

if id -Gn "$user" | tr ' ' '\n' | grep -qx "$(getent group "$cli_gid" | cut -d: -f1)" && [ "$cli_gid" != "$gid" ]; then
    note "$user is a member of the group $(getent group "$cli_gid" | cut -d: -f1) (docker_gid of params.py): what runs as $user can reach the Docker daemon."
    note "On a host that only uses the Podman engine, take $user out of that group and set docker_gid to $gid."
fi
echo "The Podman engine is ready on this host: $ranges project(s) at a time, each in a uid range of its own."
engine="$("$PYTHON" -W ignore -c 'import sys; sys.path.insert(0, sys.argv[1]); from SRE import params; print(params.host_container_engine())' "$SRC" 2>/dev/null || true)"
[ "$engine" = podman ] || note "the engine of this host is still '${engine:-unknown}': set container_engine = \"podman\" (or an entry of container_engine_by_host) in $params_file."
