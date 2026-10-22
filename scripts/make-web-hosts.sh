#!/bin/bash
# The [[hosts]] part of the web portal's web.toml (see scripts/etc/web.toml) for the machines of a
# site that get an agent, with the TLS material of every host made by scripts/web-tls.sh.
#
#   IP_MAC_FILE=<file> OUT_DIR=<dir> REGEXP=<regexp> ROOMS="<rooms>" DISABLED_ROOMS="<rooms>" \
#       scripts/make-web-hosts.sh
#
# Everything comes from environment variables.  These five are required, without default (ROOMS
# and DISABLED_ROOMS may be empty, but must be set):
#   IP_MAC_FILE     the machines of the site, one per line, three fields separated by semicolons, no
#                   header, no comment, blank lines skipped:
#                     <mac>;<ip>;<name>           e.g.  e4:54:e8:d1:6c:1c;10.0.128.1;a01
#                   <mac>   the MAC address of the host (aa:bb:cc:dd:ee:ff, any case), for Wake-on-LAN
#                   <ip>    its IPv4 address: the URL of its agent (https://<ip>:AGENT_PORT) and a SAN of
#                           its certificate
#                   <name>  its name, kept as written (name =, certificate, file names)
#   OUT_DIR         where the files listed below are written (private keys and tokens: keep it out
#                   of any repository)
#   REGEXP          a machine gets an agent when its lower-cased name matches (an extended regular
#                   expression, as bash's [[ =~ ]] reads it), e.g. '^([a-z])[0-9]+$': a letter and a
#                   number (a15, h1), the other names (f-paul, p-anna, new) ignored.  The first (...)
#                   group, when there is one, is the room of the machine
#   ROOMS           the rooms whose machines join the pool ("a h"); empty: every room, i.e. every
#                   qualified machine (the only value when REGEXP has no group)
#   DISABLED_ROOMS  the rooms whose machines start with enabled = false (polled, no project placed
#                   there until `sre-web pool enable <name>`); empty: none
# The optional ones, with the values of the documentation when unset:
#   AGENT_PORT        8451               the port of the agents (url and listen)
#   MAX_PROJECTS      25                 max_projects of every host
#   POWER             false              true: power = true (the portal may power a host off) in [[hosts]]
#                                        and allow_power_off = true in agent-<name>.toml
#   DOMAIN            none               when set, DNS:<name>.<DOMAIN> is a SAN of the certificate too
#   PORTAL_ADDRESS    none               when set, allowed_clients = ["<it>"] in agent-<name>.toml
#   TLS_DIR_ON_HOSTS  /etc/sysreseval/tls  where the hosts and the portal keep the files (the paths
#                                        written in the toml)
# A qualified machine with a bad address stops the script, as does a name, an address or a MAC given
# twice among the qualified machines of the selected rooms.
#
# Written in OUT_DIR:
#   ca.key ca.crt portal.key portal.crt   web-tls.sh init-ca and portal, once
#   <name>.key <name>.crt                 web-tls.sh agent, once per host (SANs IP:<ip>, DNS:<name>[.DOMAIN])
#   <name>.token                          the agent token of the host, drawn once (openssl rand) and kept
#   hosts.toml                            the [[hosts]] entries, one room after the other (the order of ROOMS,
#                                         else of the file), the machines in the order of the file: a file of
#                                         web.d/ (import = ["web.d"]) or pasted at the end of web.toml; the
#                                         [pool] TLS lines in its header
#   agent-<name>.toml                     the host-specific lines of the agent.toml of that host
# A second run keeps every key, certificate and token already there, adds the new hosts and
# rewrites hosts.toml and agent-*.toml, so REGEXP / ROOMS / DISABLED_ROOMS may change at any time.
set -euo pipefail

die() { echo "make-web-hosts: $*" >&2; exit 1; }
warn() { echo "make-web-hosts: $*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
in_list() {   # in_list WORD LIST: WORD is one of the space-separated LIST
    case " $2 " in *" $1 "*) return 0;; esac
    return 1
}
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

case "${1:-}" in
    '') ;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 1;;
esac
missing=""
for v in IP_MAC_FILE OUT_DIR REGEXP ROOMS DISABLED_ROOMS; do
    [ -n "${!v+set}" ] || missing="$missing $v"
done
[ -z "$missing" ] || die "not set:$missing (run with -h for the variables)"
[ -n "$IP_MAC_FILE" ] || die "IP_MAC_FILE is empty"
[ -n "$OUT_DIR" ] || die "OUT_DIR is empty"
[ -n "$REGEXP" ] || die "REGEXP is empty"
AGENT_PORT="${AGENT_PORT:-8451}"
MAX_PROJECTS="${MAX_PROJECTS:-25}"
POWER="${POWER:-false}"
DOMAIN="${DOMAIN:-}"
PORTAL_ADDRESS="${PORTAL_ADDRESS:-}"
TLS_DIR_ON_HOSTS="${TLS_DIR_ON_HOSTS:-/etc/sysreseval/tls}"

input="$IP_MAC_FILE"
web_tls="$(dirname "$0")/web-tls.sh"
out="$OUT_DIR"
[ -r "$input" ] || die "$input: not readable"
[ -r "$web_tls" ] || die "$web_tls: not found"
command -v openssl >/dev/null || die "openssl is not installed"
if [[ probe =~ $REGEXP ]]; then :; elif [ $? -eq 2 ]; then die "REGEXP '$REGEXP': bad regular expression"; fi
ROOMS=$(lower "$ROOMS"); DISABLED_ROOMS=$(lower "$DISABLED_ROOMS")
if [ -n "$ROOMS" ]; then
    for room in $DISABLED_ROOMS; do
        in_list "$room" "$ROOMS" || warn "disabled room '$room' is not in ROOMS ($ROOMS): its machines are left out"
    done
fi

# the qualified machines of the selected rooms: "name;ip;mac;room" lines, the order of the file
selected=""
lineno=0; qualified=0; roomed=0
while IFS=';' read -r mac ip name || [ -n "$name" ]; do
    lineno=$((lineno + 1))
    name=${name%$'\r'}
    [ -n "$mac$ip$name" ] || continue                   # blank line
    [[ $(lower "$name") =~ $REGEXP ]] || continue       # no agent on this machine
    room=${BASH_REMATCH[1]:-}
    qualified=$((qualified + 1))
    [ -z "$room" ] || roomed=$((roomed + 1))
    if [ -n "$ROOMS" ]; then in_list "$room" "$ROOMS" || continue; fi
    [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "$input:$lineno: bad IP address '$ip' for $name"
    mac=$(lower "$mac")
    [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || die "$input:$lineno: bad MAC address '$mac' for $name"
    selected="$selected$name;$ip;$mac;$room
"
done < "$input"
[ "$qualified" -gt 0 ] || die "no machine of $input matches REGEXP '$REGEXP'"
if [ -n "$ROOMS" ] && [ "$roomed" -eq 0 ]; then
    die "ROOMS is '$ROOMS' but REGEXP '$REGEXP' has no (...) group giving the room of a machine"
fi
[ -n "$selected" ] || die "none of the $qualified machines matching REGEXP '$REGEXP' is in the rooms '$ROOMS'"

# one room after the other: the order of ROOMS (a room without machine is reported), else the
# order of the first machine of each room in the file; a REGEXP without a group gives one room
hosts=$(printf '%s' "$selected" | awk -F';' -v rooms="$ROOMS" -v file="$input" '
    BEGIN { n = split(rooms, order, " ") }
    { if (!($4 in lines) && n == 0) order[++m] = $4; lines[$4] = lines[$4] $0 "\n" }
    END {
        if (n == 0) n = m
        for (i = 1; i <= n; i++)
            if (order[i] in lines) printf "%s", lines[order[i]]
            else print "make-web-hosts: no machine of room \047" order[i] "\047 in " file > "/dev/stderr"
    }')
for field in '1 name' '2 IP address' '3 MAC address'; do
    dup=$(printf '%s\n' "$hosts" | cut -d';' -f"${field%% *}" | sort | uniq -d | tr '\n' ' ')
    [ -z "$dup" ] || die "the same ${field#* } twice among the selected hosts of $input: $dup"
done

mkdir -p "$out"
chmod 0700 "$out"
[ -f "$out/ca.key" ] || bash "$web_tls" init-ca "$out"
[ -f "$out/portal.key" ] || bash "$web_tls" portal "$out"

hosts_toml="$out/hosts.toml"
tmp="$hosts_toml.tmp"
(umask 077; cat > "$tmp" <<EOH
# [[hosts]] of the SRE web portal (scripts/etc/web.toml), made by scripts/make-web-hosts.sh on $(date '+%Y-%m-%d %H:%M')
# from $input: names matching '$REGEXP'${ROOMS:+, rooms $ROOMS}${DISABLED_ROOMS:+, disabled at start: $DISABLED_ROOMS}.
# A file of web.d/ (web.toml: import = ["web.d"]) or pasted at the end of web.toml; owner
# root:sre-web, mode 0640.  The [pool] table of web.toml needs the CA and the portal's client
# certificate (ca.crt, portal.crt, portal.key of the same directory as the hosts' certificates):
# [pool]
# ca = "$TLS_DIR_ON_HOSTS/ca.crt"
# client_cert = "$TLS_DIR_ON_HOSTS/portal.crt"
# client_key = "$TLS_DIR_ON_HOSTS/portal.key"
EOH
)
n=0; new=0; disabled=0
while IFS=';' read -r name ip mac room; do
    [ -n "$name" ] || continue
    if [ -f "$out/$name.crt" ]; then
        openssl x509 -in "$out/$name.crt" -noout -text | grep -q -E "IP Address:$ip(,|\$)" \
            || warn "$name.crt does not name $ip: remove $out/$name.key and $out/$name.crt and run again"
    else
        bash "$web_tls" agent "$out" "$name" "IP:$ip" "DNS:$name" ${DOMAIN:+"DNS:$name.$DOMAIN"}
        new=$((new + 1))
    fi
    [ -f "$out/$name.token" ] || (umask 077; openssl rand -hex 24 > "$out/$name.token")
    token=$(cat "$out/$name.token")
    [ ${#token} -ge 32 ] || die "$out/$name.token: too short (32+ characters expected)"
    enabled=true
    if [ -n "$room" ] && in_list "$room" "$DISABLED_ROOMS"; then enabled=false; disabled=$((disabled + 1)); fi
    {
        echo
        echo '[[hosts]]'
        echo "name = \"$name\""
        echo "url = \"https://$ip:$AGENT_PORT\""
        echo "token = \"$token\""
        echo "max_projects = $MAX_PROJECTS"
        echo "mac = \"$mac\""
        if [ "$POWER" = true ]; then echo "power = true"; fi
        if [ "$enabled" = false ]; then echo "enabled = false"; fi
    } >> "$tmp"
    (umask 077; {
        echo "# The lines of $name's agent.toml (scripts/etc/agent.toml) made by scripts/make-web-hosts.sh: its"
        echo "# certificate $name.crt / $name.key and ca.crt go to $TLS_DIR_ON_HOSTS (readable by root only)."
        echo "listen = \"$ip:$AGENT_PORT\""
        echo "token = \"$token\""
        echo "tls_cert = \"$TLS_DIR_ON_HOSTS/$name.crt\""
        echo "tls_key = \"$TLS_DIR_ON_HOSTS/$name.key\""
        echo "tls_ca = \"$TLS_DIR_ON_HOSTS/ca.crt\""
        if [ -n "$PORTAL_ADDRESS" ]; then echo "allowed_clients = [\"$PORTAL_ADDRESS\"]"; fi
        if [ "$POWER" = true ]; then echo "allow_power_off = true"; fi
    } > "$out/agent-$name.toml")
    n=$((n + 1))
done <<< "$hosts"
mv "$tmp" "$hosts_toml"
echo "make-web-hosts: $n hosts ($disabled disabled at start) in $hosts_toml, $new new certificates; agent-<name>.toml next to it"
