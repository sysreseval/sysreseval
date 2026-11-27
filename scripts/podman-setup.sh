#!/bin/bash
# Prepare this host for the Podman engine of SRE (container_engine = "podman", or an entry of
# container_engine_by_host, in params.py).  Run once as root; running it again changes nothing.
#
# The machines of a project are then rootless Podman containers of the account sre_user:
#   - the account gets a range of subordinate uids and gids (/etc/subuid, /etc/subgid), large
#     enough for podman_uid_ranges projects, each in a range of its own;
#   - its systemd user manager is started at boot (loginctl enable-linger): the hubs of
#     the networks are its units, and it makes the user namespace of Podman after each boot;
#   - the directory podman_dir gets the configuration and the image store of the engine;
#   - the user namespace of the account is created, and Podman is asked to answer both as the
#     account and with the group the sre command runs with (docker_gid);
#   - the quota of kernel keys of a user is raised (/etc/sysctl.d/60-sre-podman.conf): the
#     services of a machine running systemd each use one;
#   - the services of SRE installed on the host (the web agent, the wipe at shutdown, the preload
#     of the images) are ordered after that user manager, by a drop-in each
#     (/etc/systemd/system/<unit>.d/10-sre-podman.conf): at a shutdown they stop, evaluate and
#     wipe the projects while the machines still run, where their unit files only know Docker.
# It also says what the engine would refuse on this host: a lab with a switch without the switch
# program (`make vde-switch`), a machine with an outside interface without pasta or without the
# host address sre_host_ip.
#
# The values come from params.py of this tree; each can be given in the environment instead:
# PODMAN_USER, PODMAN_DIR, PODMAN_UID_RANGES, and PODMAN_SUBID_FIRST (the first subordinate
# id, when the account has no range yet: 20000000, or above the ranges already given to other
# accounts), PODMAN_ORDERED_UNITS (the services to order, separated by spaces; empty: none).
# A registry mirror is the matter of the administrator:
# <podman_dir>/config/containers/registries.conf.
#
# `make podman-setup` runs it from a checkout.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RANGE_SIZE=65536

case "${1:-}" in
    -h|--help)
        sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
        echo "usage: $(basename "$0")"
        exit 0;;
esac

fail() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

[ "$(id -u)" = 0 ] || fail "run this script as root"

PYTHON="$ROOT/venv/bin/python"
[ -x "$PYTHON" ] || PYTHON=python3
param() {
    "$PYTHON" -W ignore -c 'import sys; sys.path.insert(0, sys.argv[1]); from SRE import params; print(getattr(params, sys.argv[2]))' \
        "$ROOT/src" "$1" || fail "cannot read $1 in $ROOT/src/SRE/params.py"
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
loginctl enable-linger "$user"
runtime="/run/user/$uid"
for _ in $(seq 60); do [ -S "$runtime/bus" ] && break; sleep 0.5; done
[ -S "$runtime/bus" ] || fail "the user manager of $user did not start (no $runtime/bus)"

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
    printf '%s\n' '# written by scripts/podman-setup.sh of SRE' '[containers]' 'keyring = false' '' \
        '[engine]' 'exit_command_delay = 1' > "$conf"
    chown "$uid:$gid" "$conf"; chmod 644 "$conf"
    echo "written: $conf"
fi

# ---- the user namespace of the account --------------------------------------------------
with_group() {      # with_group GID command...: the command as the account, with that group and no other
    local group="$1"; shift
    ( cd "$dir" && setpriv --reuid "$uid" --regid "$group" --clear-groups \
        env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 \
            HOME="$dir" USER="$user" LOGNAME="$user" XDG_RUNTIME_DIR="$runtime" \
            XDG_CONFIG_HOME="$dir/config" XDG_DATA_HOME="$dir/data" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" "$@" )
}
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
keys_conf=/etc/sysctl.d/60-sre-podman.conf
if [ "$(sysctl -n kernel.keys.maxkeys)" -lt 20000 ] || [ "$(sysctl -n kernel.keys.maxbytes)" -lt 2000000 ]; then
    install -m 0644 -o root -g root "$ROOT/scripts/etc/sre-podman.conf" "$keys_conf"
    sysctl -q -p "$keys_conf"
    echo "written: $keys_conf (kernel.keys.maxkeys = $(sysctl -n kernel.keys.maxkeys))"
fi

# ---- the order of the services of SRE ---------------------------------------------------
# A unit ordered after the user manager is stopped before it: the machines, their networks and
# the namespace of Podman are there until the services that act on the projects are done.
ordered_units=${PODMAN_ORDERED_UNITS-sre-agent.service sysreseval-agent.service sre-wipe-at-shutdown.service sre-preload-images.service sysreseval-preload-images.service}
reload=
for unit in $ordered_units; do
    systemctl cat "$unit" >/dev/null 2>&1 || continue       # not installed on this host
    dropin="/etc/systemd/system/$unit.d/10-sre-podman.conf"
    wanted="$(printf '%s\n' "# written by scripts/podman-setup.sh of SRE: the Podman engine runs in the user manager of $user" \
        '[Unit]' "Wants=user@$uid.service" "After=user@$uid.service")"
    if [ "$(cat "$dropin" 2>/dev/null)" != "$wanted" ]; then
        install -d -m 0755 "$(dirname "$dropin")"
        printf '%s\n' "$wanted" > "$dropin"
        chmod 0644 "$dropin"
        echo "written: $dropin"
        reload=1
    fi
done
[ -z "$reload" ] || systemctl daemon-reload

# ---- what a lab may need on top ---------------------------------------------------------
switch="$(param vde_switch_program)"
[ -x "$switch" ] || note "no switch program ($switch): a lab with a 'switch' or 'managed' network is refused. Build it with: make vde-switch"
command -v pasta >/dev/null 2>&1 || note "pasta is not installed (Debian package passt): a lab with an outside interface ('bridged') is refused."
host_ip="$(param sre_host_ip)"
ip -4 -o addr show | grep -q " $host_ip/" || note "no interface of this host has $host_ip (sre_host_ip; the bridge of Docker has it where Docker runs): a lab with an outside interface is refused."

if id -Gn "$user" | tr ' ' '\n' | grep -qx "$(getent group "$cli_gid" | cut -d: -f1)" && [ "$cli_gid" != "$gid" ]; then
    note "$user is a member of the group $(getent group "$cli_gid" | cut -d: -f1) (docker_gid of params.py): what runs as $user can reach the Docker daemon."
    note "On a host that only uses the Podman engine, take $user out of that group and set docker_gid to $gid."
fi
echo "The Podman engine is ready on this host: $ranges project(s) at a time, each in a uid range of its own."
