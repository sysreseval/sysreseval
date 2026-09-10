#!/bin/bash
# Reference only: a shell transcription of what src/sre-wrapper/sre-wrapper.c does.
#
# It is NOT usable as bin/sre-wrapper.  sre accepts a "--user" call only when the
# compiled sre-wrapper binary is an ancestor of the process, identified through
# /proc/<pid>/exe.  A script cannot provide that identity (its exe is the
# interpreter, and argv is caller-controlled), so sre refuses it with
# "must be launched via sre-wrapper".  Build the real wrapper with
# "make sre-wrapper" (done by "make install").

if [[ ! "$USER" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "sre-wrapper: invalid username: '$USER'" >&2
  exit 1
fi
export USER_USERNAME="$USER"
_COOKIE="$(xauth list 2>/dev/null | head -n1 | awk '{print $3}')"
if [[ "$_COOKIE" =~ ^[0-9A-Fa-f]+$ ]]; then
  export SRE_XAUTH_COOKIE="$_COOKIE"
fi
_SCRIPT="${BASH_SOURCE[0]}"
while [ -L "$_SCRIPT" ]; do _SCRIPT="$(readlink "$_SCRIPT")"; done
DIR="$(cd "$(dirname "$_SCRIPT")" && pwd)"
sudo "$DIR/../sbin/sre" --user "$@"
