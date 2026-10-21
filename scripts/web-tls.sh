#!/bin/bash
# The certificates of the SRE web site: one private CA, a certificate per pool host (the agent)
# and a client certificate for the portal, so that the portal and the agents authenticate each
# other (mutual TLS, see the "Web site" page of the documentation).
#
#   scripts/web-tls.sh init-ca <dir>                     ca.key + ca.crt (10 years) in <dir>
#   scripts/web-tls.sh agent <dir> <name> <san>...       <name>.key + <name>.crt signed by the CA (1 year);
#                                                        the SANs are the names of the agent's URL in web.toml:
#                                                        IP:10.0.0.11, DNS:a01.example.org (a bare value is
#                                                        taken as an IP address when it is one, a DNS name else)
#   scripts/web-tls.sh portal <dir> [<name>]             <name>.key + <name>.crt (default portal), a client certificate
#
# Keys are written mode 0600; nothing else is written or removed (the CSR goes through a pipe).
# Needs openssl.  Then: agent.toml tls_cert / tls_key / tls_ca, web.toml [pool] ca /
# client_cert / client_key, https:// URLs in [[hosts]].
set -euo pipefail

die() { echo "web-tls: $*" >&2; exit 1; }
usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

CA_DAYS=3650
CERT_DAYS=365

new_key() {   # new_key FILE: an EC P-256 private key, readable by its owner only
    (umask 077; openssl ecparam -genkey -name prime256v1 -noout -out "$1")
}

san_list() {  # san_list VALUE...: "IP:…,DNS:…" with the prefixes guessed when absent
    local out="" v
    for v in "$@"; do
        case "$v" in
            IP:*|DNS:*|email:*|URI:*) ;;
            *) if [[ $v =~ ^[0-9.]+$ || $v == *:* ]]; then v="IP:$v"; else v="DNS:$v"; fi;;
        esac
        out="${out:+$out,}$v"
    done
    printf '%s' "$out"
}

sign() {      # sign DIR NAME EXTENSIONS: a key and a certificate signed by DIR/ca
    local dir="$1" name="$2" extensions="$3"
    [ -f "$dir/ca.key" ] && [ -f "$dir/ca.crt" ] || die "no CA in $dir (run: $0 init-ca $dir)"
    [ -e "$dir/$name.key" ] && die "$dir/$name.key exists: not overwritten"
    new_key "$dir/$name.key"
    # the request goes through the pipe, the extensions through a process substitution: no temp file
    openssl req -new -key "$dir/$name.key" -subj "/CN=$name" \
        | openssl x509 -req -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial -days "$CERT_DAYS" -sha256 \
            -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n%s\n' \
                              "$extensions") \
            -out "$dir/$name.crt"
    chmod 0644 "$dir/$name.crt"
    echo "web-tls: $dir/$name.key and $dir/$name.crt written"
}

command -v openssl >/dev/null || die "openssl is not installed"
case "${1:-}" in
    init-ca)
        [ $# -eq 2 ] || { usage; exit 1; }
        dir="$2"; mkdir -p "$dir"
        [ -e "$dir/ca.key" ] && die "$dir/ca.key exists: not overwritten"
        new_key "$dir/ca.key"
        openssl req -x509 -new -key "$dir/ca.key" -subj "/CN=SysResEval web CA" -days "$CA_DAYS" -sha256 \
            -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash" \
            -out "$dir/ca.crt"
        chmod 0644 "$dir/ca.crt"
        echo "web-tls: CA written: $dir/ca.key (keep it private) and $dir/ca.crt (copy it to every host)";;
    agent)
        [ $# -ge 4 ] || { usage; exit 1; }
        sign "$2" "$3" "extendedKeyUsage=serverAuth
subjectAltName=$(san_list "${@:4}")";;
    portal)
        [ $# -ge 2 ] && [ $# -le 3 ] || { usage; exit 1; }
        sign "$2" "${3:-portal}" "extendedKeyUsage=clientAuth";;
    -h|--help) usage;;
    *) usage; exit 1;;
esac
