#!/bin/bash
# Build the vde_switch that the Podman engine of SRE runs for the networks of mode 'switch' and
# 'managed' (params.vde_switch_program): bin/sre-vde-switch of this tree.
#
# It is the switch of the Kathara network plugin: vde-2 at the commit the plugin pins, with the
# plugin's one change, the frame buffer of the switch raised from 1504 to 16384 bytes.  The
# vde_switch of the Debian package vde-switch has the 1504-byte buffer and loses every frame
# above 1518 bytes; this one carries what the plugs carry (9234 bytes: an MTU of 9000 and more).
#
# Needs curl, tar, cmake, make and a C compiler.  The archive is checked against its SHA-256.
# Nothing is done when the program is already there (FORCE=1 builds it again).  One build
# serves every host of the same system sharing the tree.
#
# Without network (the build of the Debian package): `--fetch FILE` downloads and checks the
# archive only, on a host that has the network, and VDE_ARCHIVE=FILE builds from it (checked
# again, no curl needed).  CFLAGS and LDFLAGS of the environment are used; VDE_KEEP_SYMBOLS=1
# leaves the program unstripped (the package build strips it and keeps the symbols apart).
#
# `make vde-switch` runs it from a checkout; the package sysreseval-podman ships the program.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${VDE_COMMIT:=306a519716493133793af39ccaf7817232e046a6}"
: "${VDE_SHA256:=a85b65c64ed2107e8ca3e4eb5018347954b87dd21e75be5b5e4187969b6a7e90}"
: "${VDE_URL:=https://github.com/virtualsquare/vde-2/archive/$VDE_COMMIT.tar.gz}"
: "${VDE_FRAME_DATA:=16384}"      # bytes of a frame after its Ethernet header (the plugin's value)
: "${VDE_SWITCH_OUT:=$ROOT/bin/sre-vde-switch}"
: "${VDE_ARCHIVE:=}"
: "${VDE_KEEP_SYMBOLS:=}"
: "${FORCE:=}"

case "${1:-}" in
    -h|--help)
        sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
        echo "usage: $(basename "$0") [--fetch FILE]    environment: FORCE=1 (build again), VDE_SWITCH_OUT (where to install it), VDE_ARCHIVE (a local archive)"
        exit 0;;
esac

fail() { echo "ERROR: $*" >&2; exit 1; }
checked() {     # checked FILE: the archive is the one pinned here
    local sum
    if command -v sha256sum >/dev/null 2>&1; then sum="$(sha256sum "$1")"; else sum="$(shasum -a 256 "$1")"; fi
    [ "${sum%% *}" = "$VDE_SHA256" ] || fail "unexpected SHA-256 for $1: ${sum%% *}"
}
fetch() {       # fetch FILE: download the archive there
    command -v curl >/dev/null 2>&1 || fail "not installed: curl"
    echo "Downloading vde-2 ${VDE_COMMIT:0:12}"
    curl -fsSL -o "$1" "$VDE_URL" || fail "cannot download $VDE_URL"
    checked "$1"
}

if [ "${1:-}" = --fetch ]; then
    [ -n "${2:-}" ] || fail "--fetch needs the file to write"
    fetch "$2"
    exit 0
fi

if [ -x "$VDE_SWITCH_OUT" ] && [ -z "$FORCE" ]; then
    echo "already built: $VDE_SWITCH_OUT (FORCE=1 builds it again)"
    exit 0
fi
missing=""
for program in tar cmake make cc; do
    command -v "$program" >/dev/null 2>&1 || missing="$missing $program"
done
[ -z "$missing" ] || fail "not installed:$missing (Debian packages: curl tar cmake make gcc)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if [ -n "$VDE_ARCHIVE" ]; then
    [ -f "$VDE_ARCHIVE" ] || fail "no archive $VDE_ARCHIVE (VDE_ARCHIVE)"
    checked "$VDE_ARCHIVE"
    cp "$VDE_ARCHIVE" "$tmp/vde-2.tar.gz"
else
    fetch "$tmp/vde-2.tar.gz"
fi
tar -xzf "$tmp/vde-2.tar.gz" -C "$tmp"
src="$tmp/vde-2-$VDE_COMMIT"

# the one change: the bytes a frame may hold after its header
header="$src/src/vde_switch/port.h"
[ "$(grep -c 'unsigned char data\[1504\];' "$header")" = 1 ] || fail "$header is not the file expected (no 1504-byte frame buffer)"
sed -i.orig "s/unsigned char data\[1504\];/unsigned char data[$VDE_FRAME_DATA];/" "$header"
grep -q "unsigned char data\[$VDE_FRAME_DATA\];" "$header" || fail "the frame buffer of $header was not changed"

# the plugin's options; only the switch is built.  The C of 2017: these sources declare
# functions without their arguments, which the default of GCC 15 and later (C23) refuses.
mkdir "$src/build"
( cd "$src/build" \
  && cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_CRYPTCAB=OFF -DENABLE_VDE_OVER_NS=OFF -DENABLE_ROUTER=OFF \
           -DENABLE_VXLAN=OFF -DENABLE_TUNTAP=OFF -DENABLE_PCAP=OFF \
           -DCMAKE_C_FLAGS="${CFLAGS:-} -std=gnu17" .. >"$tmp/cmake.log" 2>&1 \
  && cmake --build . --target vde_switch >"$tmp/build.log" 2>&1 ) \
  || { cat "$tmp/cmake.log" "$tmp/build.log" 2>/dev/null | tail -40 >&2 || true; fail "the build failed"; }
built="$(find "$src/build" -type f -name vde_switch -perm -u+x | head -1)"
[ -n "$built" ] || fail "no vde_switch was built"
[ -n "$VDE_KEEP_SYMBOLS" ] || strip "$built" 2>/dev/null || true
install -d "$(dirname "$VDE_SWITCH_OUT")"
install -m 755 "$built" "$VDE_SWITCH_OUT"
echo "built: $VDE_SWITCH_OUT ($("$VDE_SWITCH_OUT" --version 2>&1 | head -1), frames of up to $((VDE_FRAME_DATA + 14)) bytes)"
