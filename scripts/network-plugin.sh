#!/bin/bash
# Install the Kathara network plugin that knows the switch types (hub, switch, managed switch) in
# place of the stock kathara/katharanp_vde:<arch>.  Run as root or as a member of the docker group.
#
# The plugin is downloaded from Docker Hub ($NETWORK_PLUGIN_IMAGE) when it is published there,
# built from the sources of $NETWORK_PLUGIN_REPO otherwise or with BUILD=1 (needs docker with
# buildx, git and python3).  Nothing is done when the installed plugin already has the switch
# types (FORCE=1 installs it again); the script refuses to run while a Kathara network exists,
# since the stock plugin is removed first.
#
# `make network-plugin` runs it from a checkout; the Debian package installs it as
# /usr/sbin/sysreseval-network-plugin.  Only labs with 'switch' / 'managed' networks need it.
set -e

: "${NETWORK_PLUGIN_REPO:=https://github.com/emotchane/NetworkPlugin.git}"
: "${NETWORK_PLUGIN_BRANCH:=main}"
: "${NETWORK_PLUGIN_NAME:=kathara/katharanp_vde}"
: "${NETWORK_PLUGIN_IMAGE:=sysreseval/katharanp_vde}"
: "${NETWORK_PLUGIN_MODES_ENV:=KATHARA_SWITCH_MODES}"
: "${NETWORK_PLUGIN_DIR:=}"      # where the sources are cloned for a build (default: a temporary directory)
: "${FORCE:=}"
: "${BUILD:=}"

case "${1:-}" in
    -h|--help)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
        echo "usage: $(basename "$0")    environment: FORCE=1 (install again), BUILD=1 (build from the sources)"
        exit 0;;
esac

case "$(uname -m)" in
    x86_64) arch=amd64;;
    aarch64|arm64) arch=arm64;;
    *) echo "ERROR: unsupported architecture $(uname -m)"; exit 1;;
esac
plugin="$NETWORK_PLUGIN_NAME:$arch"
docker info >/dev/null 2>&1 || { echo "ERROR: the Docker daemon is not reachable"; exit 1; }
has_modes() {
    docker plugin inspect "$plugin" --format '{{.Settings.Env}}' 2>/dev/null | grep -q "$NETWORK_PLUGIN_MODES_ENV="
}
if [ -z "$FORCE" ] && has_modes; then
    docker plugin enable "$plugin" >/dev/null 2>&1 || true
    echo "Network plugin $plugin already has the switch types"
    exit 0
fi
networks=$(docker network ls -q --filter "driver=$plugin" | wc -l)
if [ "$networks" -ne 0 ]; then
    echo "ERROR: $networks network(s) use $plugin: stop the running projects first (sre wipe)"
    exit 1
fi
docker plugin rm -f "$plugin" >/dev/null 2>&1 || true
if [ -z "$BUILD" ]; then
    image="$NETWORK_PLUGIN_IMAGE:$arch"
    if docker plugin install --grant-all-permissions --alias "$plugin" "$image" && has_modes; then
        echo "Network plugin $plugin installed from $image: hub, switch and managed switch"
        exit 0
    fi
    echo "No usable plugin published as $image: building it from the sources"
    docker plugin rm -f "$plugin" >/dev/null 2>&1 || true
fi
builddir="$NETWORK_PLUGIN_DIR"
[ -n "$builddir" ] || builddir="$(mktemp -d)"
rm -rf "$builddir"
mkdir -p "$(dirname "$builddir")"
git clone --depth 1 --branch "$NETWORK_PLUGIN_BRANCH" "$NETWORK_PLUGIN_REPO" "$builddir"
build="make -C $builddir/vde all_$arch PLUGIN_NAME=$NETWORK_PLUGIN_NAME"
echo "Building $plugin (a few minutes)"
if [ -t 0 ]; then $build; else script -qefc "$build" /dev/null; fi
docker plugin enable "$plugin"
rm -rf "$builddir"
has_modes || { echo "ERROR: $plugin does not advertise $NETWORK_PLUGIN_MODES_ENV"; exit 1; }
echo "Network plugin $plugin built and installed: hub, switch and managed switch"
