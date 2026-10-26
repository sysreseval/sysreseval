#!/bin/bash
# The [[hosts]] part of the web portal's web.toml (see scripts/etc/web.toml) for the machines of a
# site that get an agent, with the TLS material of every host made by scripts/web-tls.sh.
#
#   IP_MAC_FILE=<file> OUT_DIR=<dir> REGEXP=<regexp> ROOMS="<rooms>" DISABLED_ROOMS="<rooms>" \
#       scripts/make-web-hosts.sh [--keep]
#
# The one option:
#   --keep          keep the agent files already in OUT_DIR (<name>.key + <name>.crt when both exist,
#                   <name>.token) and build only the missing ones: a room is added without touching
#                   the hosts already deployed (their hosts.toml entry and agent-<name>.toml still
#                   follow the variables, see below).  Without it every selected host gets a new
#                   key, a new certificate and a new token on each run, to deploy again.
# Everything else comes from environment variables.  These five are required, without default
# (ROOMS and DISABLED_ROOMS may be empty, but must be set):
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
#                   there until `sre-web-tool enable <name>`); empty: none
# The optional ones, with the values of the documentation when unset:
#   AGENT_PORT          8451             the port of the agents (url of the portal, listen of the agent)
#   MAX_PROJECTS        25               max_projects of every host
#   POWER               false            true: power = true (the portal may power a host off) in [[hosts]]
#                                        and allow_power_off = true in agent-<name>.toml
#   INSTRUCTOR_ROOMS    none             the rooms whose hosts get instructors_only = true (only the
#                                        instructors' projects are placed there, they choose them on their
#                                        Open page); a room may be in DISABLED_ROOMS too
#   INSTRUCTOR_MACHINES none             the machines ("s0 h3", names as in the file, any case) whose host
#                                        gets instructors_only = true on its own, whatever its room; a name
#                                        that is not one of the selected hosts is reported and ignored
#   DOMAIN              none             when set, DNS:<name>.<DOMAIN> is a SAN of the certificate too
#   PORTAL_ADDRESS      none             when set, allowed_clients = ["<it>"] in agent-<name>.toml
#   TLS_DIR_ON_HOSTS    /etc/sreweb/tls  where the hosts and the portal keep the files (the paths
#                                        written in the toml)
#   CA_KEY, CA_CRT      none             both set: the private key and the certificate of an existing CA
#                                        (an earlier OUT_DIR, the files already deployed), copied into
#                                        OUT_DIR as ca.key / ca.crt instead of a new CA, so that the new
#                                        hosts are signed by the CA the portal and the other hosts know;
#                                        the key must be the certificate's; refused when OUT_DIR already
#                                        holds another CA
# A qualified machine with a bad address stops the script, as does a name, an address or a MAC given
# twice among the qualified machines of the selected rooms.
#
# Written in OUT_DIR:
#   ca.key ca.crt                         web-tls.sh init-ca once, or the copy of CA_KEY / CA_CRT
#   portal.key portal.crt                 web-tls.sh portal, once
#   <name>.key <name>.crt                 web-tls.sh agent, per host (SANs IP:<ip>, DNS:<name>[.DOMAIN])
#   <name>.token                          the agent token of the host (openssl rand)
#   hosts.toml                            the [[hosts]] entries, one room after the other (the order of ROOMS,
#                                         else of the file), the machines in the order of the file: a file of
#                                         web.d/ (import = ["web.d"]) or pasted at the end of web.toml; the
#                                         [pool] TLS lines in its header
#   agent-<name>.toml                     the host-specific lines of the agent.toml of that host (listen =
#                                         "<ip>:AGENT_PORT", token, tls_*, allowed_clients, allow_power_off;
#                                         the shared agent.toml must then have no listen line)
# Every run computes hosts.toml and every agent-<name>.toml from the variables of the moment (REGEXP /
# ROOMS / DISABLED_ROOMS / INSTRUCTOR_ROOMS / INSTRUCTOR_MACHINES / POWER... may change at any time)
# and compares them with the files of the previous run: a file whose content did not change is left
# as it is (its date too), the others are replaced, and what changed is printed per host (hosts.toml:
# enabled, instructors_only, url, max_projects, mac, power; agent-<name>.toml: listen, tls_*,
# allowed_clients, allow_power_off), with the new hosts and those no longer selected (their entry is
# dropped, their files are left in OUT_DIR); the last line says whether hosts.toml and which
# agent-<name>.toml are to deploy again.  The CA and the portal's certificate are made once and kept.
# The hosts' keys, certificates and tokens are made anew on every run unless --keep is given: the
# files present are then kept (a kept certificate that no longer names the address of its host is
# reported) and only those of the new hosts are made.
set -euo pipefail

die() { echo "make-web-hosts: $*" >&2; exit 1; }
warn() { echo "make-web-hosts: $*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
in_list() {   # in_list WORD LIST: WORD is one of the space-separated LIST
    case " $2 " in *" $1 "*) return 0;; esac
    return 1
}
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
entries_of() {   # entries_of FILE: the [[hosts]] entries of a hosts.toml, one line each, to compare two runs:
                 # "name;url;token;max_projects;mac;power;enabled;instructors_only" (the default of a key left out)
    [ -f "$1" ] || return 0
    awk '
        function reset() { split("", v); v["power"] = "false"; v["enabled"] = "true"; v["instructors_only"] = "false" }
        function flush() {
            if (name != "")
                print name ";" v["url"] ";" v["token"] ";" v["max_projects"] ";" v["mac"] ";" v["power"] ";" v["enabled"] ";" v["instructors_only"]
            name = ""; reset()
        }
        BEGIN { reset() }
        /^\[\[hosts\]\]/ { flush(); next }
        /^[a-z_]+ *= */ {
            key = $0; sub(/ *=.*$/, "", key)
            val = $0; sub(/^[a-z_]+ *= */, "", val); gsub(/^"|"$/, "", val)
            if (key == "name") name = val; else v[key] = val
        }
        END { flush() }' "$1"
}
entry_of() {   # entry_of NAME LINES: the line of host NAME among the entry LINES, "" when absent
    printf '%s\n' "$2" | awk -F';' -v n="$1" '$1 == n { print; exit }'
}
entry_changes() {   # entry_changes OLD NEW [ignore_token]: what differs between two entry lines, "" when nothing
    local name o_url o_token o_max o_mac o_power o_enabled o_instr n_url n_token n_max n_mac n_power n_enabled n_instr changes=""
    IFS=';' read -r name o_url o_token o_max o_mac o_power o_enabled o_instr <<< "$1"
    IFS=';' read -r name n_url n_token n_max n_mac n_power n_enabled n_instr <<< "$2"
    [ "${3:-}" != ignore_token ] || o_token=$n_token
    [ "$o_url" = "$n_url" ] || changes="$changes, url $o_url -> $n_url"
    [ "$o_token" = "$n_token" ] || changes="$changes, token"
    [ "$o_max" = "$n_max" ] || changes="$changes, max_projects $o_max -> $n_max"
    [ "$o_mac" = "$n_mac" ] || changes="$changes, mac $o_mac -> $n_mac"
    [ "$o_power" = "$n_power" ] || changes="$changes, power $o_power -> $n_power"
    [ "$o_enabled" = "$n_enabled" ] || changes="$changes, enabled $o_enabled -> $n_enabled"
    [ "$o_instr" = "$n_instr" ] || changes="$changes, instructors_only $o_instr -> $n_instr"
    printf '%s' "${changes#, }"
}
agent_changes() {   # agent_changes OLD NEW [ignore_token]: the keys whose line differs between two agent-<name>.toml,
                    # "comments" when only the comments do, "" when nothing (a token change is ignored when asked)
    local key o n changes="" token_differs=false
    cmp -s "$1" "$2" && return 0
    for key in listen token tls_cert tls_key tls_ca allowed_clients allow_power_off; do
        o=$(grep "^$key = " "$1" || true); n=$(grep "^$key = " "$2" || true)
        [ "$o" != "$n" ] || continue
        if [ "$key" = token ]; then
            token_differs=true
            if [ "${3:-}" = ignore_token ]; then continue; fi
        fi
        changes="$changes, $key"
    done
    [ -n "$changes" ] || [ "$token_differs" = true ] || changes=", comments"
    printf '%s' "${changes#, }"
}

KEEP=false
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=true;;
        -h|--help) usage; exit 0;;
        *) echo "make-web-hosts: unknown argument '$arg'" >&2; usage >&2; exit 1;;
    esac
done
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
INSTRUCTOR_ROOMS="${INSTRUCTOR_ROOMS:-}"
INSTRUCTOR_MACHINES="${INSTRUCTOR_MACHINES:-}"
DOMAIN="${DOMAIN:-}"
PORTAL_ADDRESS="${PORTAL_ADDRESS:-}"
TLS_DIR_ON_HOSTS="${TLS_DIR_ON_HOSTS:-/etc/sreweb/tls}"
CA_KEY="${CA_KEY:-}"
CA_CRT="${CA_CRT:-}"

input="$IP_MAC_FILE"
web_tls="$(dirname "$0")/web-tls.sh"
out="$OUT_DIR"
[ -r "$input" ] || die "$input: not readable"
[ -r "$web_tls" ] || die "$web_tls: not found"
command -v openssl >/dev/null || die "openssl is not installed"
if [ -n "$CA_KEY$CA_CRT" ]; then
    [ -n "$CA_KEY" ] && [ -n "$CA_CRT" ] || die "CA_KEY and CA_CRT go together (the private key and the certificate of the CA)"
    [ -r "$CA_KEY" ] || die "CA_KEY $CA_KEY: not readable"
    [ -r "$CA_CRT" ] || die "CA_CRT $CA_CRT: not readable"
    openssl x509 -in "$CA_CRT" -noout -text | grep -q 'CA:TRUE' || die "CA_CRT $CA_CRT: not a CA certificate"
    [ "$(openssl x509 -in "$CA_CRT" -noout -pubkey)" = "$(openssl pkey -in "$CA_KEY" -pubout)" ] \
        || die "CA_KEY $CA_KEY is not the private key of CA_CRT $CA_CRT"
fi
if [[ probe =~ $REGEXP ]]; then :; elif [ $? -eq 2 ]; then die "REGEXP '$REGEXP': bad regular expression"; fi
ROOMS=$(lower "$ROOMS"); DISABLED_ROOMS=$(lower "$DISABLED_ROOMS")
INSTRUCTOR_ROOMS=$(lower "$INSTRUCTOR_ROOMS"); INSTRUCTOR_MACHINES=$(lower "$INSTRUCTOR_MACHINES")
if [ -n "$ROOMS" ]; then
    for room in $DISABLED_ROOMS; do
        in_list "$room" "$ROOMS" || warn "disabled room '$room' is not in ROOMS ($ROOMS): its machines are left out"
    done
    for room in $INSTRUCTOR_ROOMS; do
        in_list "$room" "$ROOMS" || warn "instructor room '$room' is not in ROOMS ($ROOMS): its machines are left out"
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
selected_names=$(printf '%s\n' "$hosts" | cut -d';' -f1 | tr '[:upper:]' '[:lower:]' | tr '\n' ' ')
for machine in $INSTRUCTOR_MACHINES; do
    in_list "$machine" "$selected_names" || warn "instructor machine '$machine' is not one of the selected hosts: ignored"
done

mkdir -p "$out"
chmod 0700 "$out"
if [ -z "$CA_KEY" ]; then
    [ -f "$out/ca.key" ] || bash "$web_tls" init-ca "$out"
elif [ -f "$out/ca.key" ]; then
    [ "$(openssl x509 -in "$out/ca.crt" -noout -fingerprint -sha256)" = "$(openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256)" ] \
        || die "$out holds another CA than $CA_CRT: remove its ca.key / ca.crt and the certificates they signed, or unset CA_KEY / CA_CRT"
else
    install -m 0600 "$CA_KEY" "$out/ca.key"
    install -m 0644 "$CA_CRT" "$out/ca.crt"
    echo "make-web-hosts: CA copied from $CA_KEY and $CA_CRT"
fi
[ -f "$out/portal.key" ] || bash "$web_tls" portal "$out"

hosts_toml="$out/hosts.toml"
tmp="$hosts_toml.tmp"
first_run=true; [ ! -f "$hosts_toml" ] || first_run=false
old_entries=$(entries_of "$hosts_toml")                          # the previous run, to report what changes
ignore_token=""; [ "$KEEP" = true ] || ignore_token=ignore_token  # tokens made anew: not a change of one host
(umask 077; cat > "$tmp" <<EOH
# [[hosts]] of the SRE web portal (scripts/etc/web.toml), made by scripts/make-web-hosts.sh on $(date '+%Y-%m-%d %H:%M')
# from $input: names matching '$REGEXP'${ROOMS:+, rooms $ROOMS}${DISABLED_ROOMS:+, disabled at start: $DISABLED_ROOMS}${INSTRUCTOR_ROOMS:+, instructor rooms: $INSTRUCTOR_ROOMS}${INSTRUCTOR_MACHINES:+, instructor machines: $INSTRUCTOR_MACHINES}.
# A file of web.d/ (web.toml: import = ["web.d"]) or pasted at the end of web.toml; owner
# root:sre-web, mode 0640.  The [pool] table of web.toml needs the CA and the portal's client
# certificate (ca.crt, portal.crt, portal.key of the same directory as the hosts' certificates):
# [pool]
# ca = "$TLS_DIR_ON_HOSTS/ca.crt"
# client_cert = "$TLS_DIR_ON_HOSTS/portal.crt"
# client_key = "$TLS_DIR_ON_HOSTS/portal.key"
EOH
)
n=0; new=0; kept=0; disabled=0; instructors=0
new_entries=""; added=0; changed=0; agents_changed=""
while IFS=';' read -r name ip mac room; do
    [ -n "$name" ] || continue
    if [ "$KEEP" = true ] && [ -f "$out/$name.key" ] && [ -f "$out/$name.crt" ]; then
        openssl x509 -in "$out/$name.crt" -noout -text | grep -q -E "IP Address:$ip(,|\$)" \
            || warn "$name.crt does not name $ip: run again without --keep, or remove $out/$name.key and $out/$name.crt"
        kept=$((kept + 1))
    else
        rm -f "$out/$name.key" "$out/$name.crt"     # web-tls.sh never overwrites a key
        bash "$web_tls" agent "$out" "$name" "IP:$ip" "DNS:$name" ${DOMAIN:+"DNS:$name.$DOMAIN"}
        new=$((new + 1))
    fi
    if [ "$KEEP" != true ] || [ ! -f "$out/$name.token" ]; then
        (umask 077; openssl rand -hex 24 > "$out/$name.token")
    fi
    token=$(cat "$out/$name.token")
    [ ${#token} -ge 32 ] || die "$out/$name.token: too short (32+ characters expected)"
    enabled=true
    if [ -n "$room" ] && in_list "$room" "$DISABLED_ROOMS"; then enabled=false; disabled=$((disabled + 1)); fi
    instructors_only=false
    if { [ -n "$room" ] && in_list "$room" "$INSTRUCTOR_ROOMS"; } || in_list "$(lower "$name")" "$INSTRUCTOR_MACHINES"; then
        instructors_only=true; instructors=$((instructors + 1))
    fi
    power=false; [ "$POWER" != true ] || power=true
    entry="$name;https://$ip:$AGENT_PORT;$token;$MAX_PROJECTS;$mac;$power;$enabled;$instructors_only"
    new_entries="$new_entries$entry
"
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
        if [ "$instructors_only" = true ]; then echo "instructors_only = true"; fi
    } >> "$tmp"
    agent_toml="$out/agent-$name.toml"
    (umask 077; {
        echo "# The lines of $name's agent.toml (scripts/etc/agent.toml) made by scripts/make-web-hosts.sh: its"
        echo "# certificate $name.crt / $name.key and ca.crt go to $TLS_DIR_ON_HOSTS (readable by root only)."
        echo "# listen is the address the portal connects to: the shared agent.toml must have no listen line"
        echo "# (a key given twice is refused)."
        echo "listen = \"$ip:$AGENT_PORT\""
        echo "token = \"$token\""
        echo "tls_cert = \"$TLS_DIR_ON_HOSTS/$name.crt\""
        echo "tls_key = \"$TLS_DIR_ON_HOSTS/$name.key\""
        echo "tls_ca = \"$TLS_DIR_ON_HOSTS/ca.crt\""
        if [ -n "$PORTAL_ADDRESS" ]; then echo "allowed_clients = [\"$PORTAL_ADDRESS\"]"; fi
        if [ "$POWER" = true ]; then echo "allow_power_off = true"; fi
    } > "$agent_toml.tmp")
    # the agent file is replaced only when its content changed; what changed since the previous run
    # is reported per host (nothing on the first run, when everything is new)
    agent_diff=""
    if [ ! -f "$agent_toml" ]; then
        mv "$agent_toml.tmp" "$agent_toml"; agents_changed="$agents_changed $name"
    elif cmp -s "$agent_toml" "$agent_toml.tmp"; then
        rm -f "$agent_toml.tmp"
    else
        agent_diff=$(agent_changes "$agent_toml" "$agent_toml.tmp" $ignore_token)
        mv "$agent_toml.tmp" "$agent_toml"; agents_changed="$agents_changed $name"
    fi
    report=""
    if [ "$first_run" = true ]; then
        :
    elif old=$(entry_of "$name" "$old_entries") && [ -z "$old" ]; then
        added=$((added + 1)); report="new host"
    else
        host_diff=$(entry_changes "$old" "$entry" $ignore_token)
        if [ -n "$host_diff" ]; then changed=$((changed + 1)); report="hosts.toml: $host_diff"; fi
        if [ -n "$agent_diff" ]; then report="${report:+$report; }agent-$name.toml: $agent_diff"; fi
    fi
    [ -z "$report" ] || echo "make-web-hosts: $name: $report"
    n=$((n + 1))
done <<< "$hosts"

# the hosts of the previous run that are not selected any more, and the files left of hosts not selected
dropped=0
for name in $(printf '%s\n' "$old_entries" | cut -d';' -f1); do
    [ -z "$(entry_of "$name" "$new_entries")" ] || continue
    dropped=$((dropped + 1))
    echo "make-web-hosts: $name: no longer selected, its [[hosts]] entry is dropped"
done
stale=""
for name in $( (cd "$out" && ls agent-*.toml ./*.key ./*.crt ./*.token 2>/dev/null) | sed -E 's#^\./##; s/^agent-//; s/\.(toml|key|crt|token)$//' | sort -u); do
    case "$name" in ca|portal) continue;; esac
    [ -z "$(entry_of "$name" "$new_entries")" ] || continue
    stale="$stale $name"
done
[ -z "$stale" ] || echo "make-web-hosts: files of hosts not selected (agent-<name>.toml, <name>.key / .crt / .token) left in $out:$stale"

# hosts.toml is replaced only when something but the date of its header changed
if [ "$first_run" = false ] && [ "$(tail -n +2 "$tmp")" = "$(tail -n +2 "$hosts_toml")" ]; then
    rm -f "$tmp"; hosts_status="unchanged"
else
    mv "$tmp" "$hosts_toml"
    if [ "$first_run" = true ]; then
        hosts_status="created"
    else
        why=""
        [ "$changed" -eq 0 ] || why="$why, $changed entries changed"
        [ "$added" -eq 0 ] || why="$why, $added new"
        [ "$dropped" -eq 0 ] || why="$why, $dropped dropped"
        [ "$KEEP" = true ] || why="$why, tokens made anew"
        hosts_status="rewritten (${why#, }), to deploy on the portal"; [ -n "$why" ] || hosts_status="rewritten (header only)"
    fi
fi
agents_changed=${agents_changed# }
if [ "$first_run" = true ]; then agents_status="agent-<name>.toml created for every host"
elif [ -z "$agents_changed" ]; then agents_status="no agent-<name>.toml changed"
elif [ "$KEEP" != true ]; then agents_status="every agent-<name>.toml rewritten (tokens made anew), to deploy on the hosts"
else agents_status="agent-<name>.toml changed for $agents_changed, to deploy on those hosts"
fi
if [ "$KEEP" = true ]; then made="$new new certificates, $kept kept (--keep)"; else made="$new certificates and tokens made anew"; fi
echo "make-web-hosts: $n hosts ($disabled disabled at start, $instructors instructors only) in $hosts_toml, $made; agent-<name>.toml next to it"
echo "make-web-hosts: hosts.toml $hosts_status; $agents_status"
