#!/bin/bash
# Build the apt repository of SysResEval from .deb files: one suite per Debian release, the packages
# told apart by the ~<dist>N suffix of their version (what scripts/build-deb.sh gives them), the
# metadata signed with the key given in the environment.  The output directory is emptied first:
# the repository is always rebuilt from the whole set of packages (the pages workflow passes the
# assets of every GitHub release, so a release is the only state).
#
#   scripts/apt-repo.sh --out site/apt --url https://sysreseval.github.io/sysreseval/apt --sign \
#       build/deb/trixie/*/*.deb build/deb/forky
#
# Options: --out DIR            where the repository is written (required, emptied)
#          --url BASE_URL       what the generated .sources files and index.html point to (required)
#          --sign               sign Release (InRelease, Release.gpg) with APT_SIGNING_KEY, the
#                               armored private key given in the environment; the public key is
#                               published as sysreseval-archive-keyring.gpg.  Without it the
#                               repository is unsigned and documented with trusted=yes
#          --origin NAME        Origin / Label of the Release files (default SysResEval)
#          --keep-dbgsym        keep the *-dbgsym packages (dropped by default)
# Needs dpkg-deb, dpkg-scanpackages (dpkg-dev), apt-ftparchive (apt-utils) and gpg: a Debian or
# Ubuntu host, or a debian container.
set -euo pipefail

die() { echo "apt-repo: $*" >&2; exit 1; }

OUT=""; URL=""; SIGN=0; ORIGIN=SysResEval; KEEP_DBGSYM=0; INPUTS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2;;
        --url) URL="$2"; shift 2;;
        --sign) SIGN=1; shift;;
        --origin) ORIGIN="$2"; shift 2;;
        --keep-dbgsym) KEEP_DBGSYM=1; shift;;
        -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        -*) die "unknown option $1";;
        *) INPUTS+=("$1"); shift;;
    esac
done
[ -n "$OUT" ] || die "--out DIR is required"
[ -n "$URL" ] || die "--url BASE_URL is required"
[ ${#INPUTS[@]} -gt 0 ] || die "no .deb file or directory given"
for tool in dpkg-deb dpkg-scanpackages apt-ftparchive; do
    command -v "$tool" >/dev/null || die "$tool is missing (dpkg-dev, apt-utils)"
done
if [ "$SIGN" = 1 ]; then
    command -v gpg >/dev/null || die "gpg is missing"
    [ -n "${APT_SIGNING_KEY:-}" ] || die "--sign needs the armored private key in APT_SIGNING_KEY"
fi
URL="${URL%/}"

# --- the packages, sorted by suite ---------------------------------------------------------------
debs=()
for input in "${INPUTS[@]}"; do
    if [ -d "$input" ]; then
        while IFS= read -r f; do debs+=("$f"); done < <(find "$input" -name '*.deb' -type f | sort)
    elif [ -f "$input" ]; then
        debs+=("$input")
    else
        die "$input: no such file or directory"
    fi
done
rm -rf "$OUT"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
declare -A dist_of=() arch_of=()
unsuffixed=()
dists=()
for f in "${debs[@]}"; do
    name=$(basename "$f")
    if [ "$KEEP_DBGSYM" = 0 ]; then
        case "$name" in *-dbgsym_*) continue;; esac
    fi
    version=$(dpkg-deb -f "$f" Version)
    arch=$(dpkg-deb -f "$f" Architecture)
    if [[ "$version" =~ ~([a-z]+)[0-9]*$ ]]; then
        dist="${BASH_REMATCH[1]}"
        mkdir -p "$OUT/pool/$dist/main"
        cp "$f" "$OUT/pool/$dist/main/$name"
        dist_of["$dist"]=1
        arch_of["$dist $arch"]=1
    else
        unsuffixed+=("$f")        # a package for every suite (no ~<dist> in its version)
    fi
done
[ ${#dist_of[@]} -gt 0 ] || die "no package with a ~<dist> version suffix among the inputs"
for dist in "${!dist_of[@]}"; do dists+=("$dist"); done
IFS=$'\n' dists=($(sort <<<"${dists[*]}")); unset IFS
for f in "${unsuffixed[@]}"; do
    arch=$(dpkg-deb -f "$f" Architecture)
    for dist in "${dists[@]}"; do
        cp "$f" "$OUT/pool/$dist/main/$(basename "$f")"
        arch_of["$dist $arch"]=1
    done
done

# --- the signing key -----------------------------------------------------------------------------
fpr=""
if [ "$SIGN" = 1 ]; then
    export GNUPGHOME
    GNUPGHOME=$(mktemp -d)
    chmod 700 "$GNUPGHOME"
    trap 'rm -rf "$GNUPGHOME"' EXIT
    printf '%s\n' "$APT_SIGNING_KEY" | gpg --batch --quiet --import
    fpr=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr/ {print $10; exit}')
    [ -n "$fpr" ] || die "no secret key in APT_SIGNING_KEY"
    gpg --batch --export "$fpr" > "$OUT/sysreseval-archive-keyring.gpg"
    gpg --batch --armor --export "$fpr" > "$OUT/sysreseval-archive-keyring.asc"
fi

# --- Packages, Release, signatures, per suite -----------------------------------------------------
cd "$OUT"
for dist in "${dists[@]}"; do
    arches=()
    for key in "${!arch_of[@]}"; do
        case "$key" in "$dist "*) a="${key#* }"; [ "$a" = all ] || arches+=("$a");; esac
    done
    [ ${#arches[@]} -gt 0 ] || arches=(amd64)
    IFS=$'\n' arches=($(sort <<<"${arches[*]}")); unset IFS
    for arch in "${arches[@]}"; do
        mkdir -p "dists/$dist/main/binary-$arch"
        # -m: every version of a package is listed (apt takes the highest, the others stay installable)
        dpkg-scanpackages --arch "$arch" --multiversion "pool/$dist" /dev/null 2>/dev/null \
            > "dists/$dist/main/binary-$arch/Packages"
        gzip -9 -c "dists/$dist/main/binary-$arch/Packages" > "dists/$dist/main/binary-$arch/Packages.gz"
    done
    apt-ftparchive \
        -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
        -o "APT::FTPArchive::Release::Label=$ORIGIN" \
        -o "APT::FTPArchive::Release::Suite=$dist" \
        -o "APT::FTPArchive::Release::Codename=$dist" \
        -o "APT::FTPArchive::Release::Architectures=${arches[*]}" \
        -o "APT::FTPArchive::Release::Components=main" \
        -o "APT::FTPArchive::Release::Description=$ORIGIN packages for Debian $dist" \
        release "dists/$dist" > "dists/$dist/Release"
    if [ "$SIGN" = 1 ]; then
        gpg --batch --yes --quiet -u "$fpr" -abs -o "dists/$dist/Release.gpg" "dists/$dist/Release"
        gpg --batch --yes --quiet -u "$fpr" --clearsign -o "dists/$dist/InRelease" "dists/$dist/Release"
    fi
    if [ "$SIGN" = 1 ]; then
        cat > "sysreseval-$dist.sources" <<SOURCES
Types: deb
URIs: $URL
Suites: $dist
Components: main
Signed-By: /usr/share/keyrings/sysreseval-archive-keyring.gpg
SOURCES
    else
        cat > "sysreseval-$dist.sources" <<SOURCES
Types: deb
URIs: $URL
Suites: $dist
Components: main
Trusted: yes
SOURCES
    fi
done

# --- index.html ------------------------------------------------------------------------------------
{
    cat <<HTML
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>$ORIGIN apt repository</title>
<style>body{font-family:sans-serif;max-width:60em;margin:2em auto;padding:0 1em}pre{background:#f4f4f4;padding:.8em;overflow-x:auto}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.2em .6em;text-align:left}</style>
</head><body>
<h1>$ORIGIN apt repository</h1>
<p>Debian packages of <a href="https://github.com/sysreseval/sysreseval">SysResEval</a>: <code>sysreseval</code>,
<code>sysreseval-doc</code>, <code>python3-kathara</code> (the SysResEval fork of Kathara) and, where Debian
does not ship it, <code>python3-fs</code>. Built from the GitHub releases.</p>
HTML
    for dist in "${dists[@]}"; do
        echo "<h2>Debian $dist</h2>"
        if [ "$SIGN" = 1 ]; then
            cat <<HTML
<pre>sudo curl -fsSL -o /usr/share/keyrings/sysreseval-archive-keyring.gpg $URL/sysreseval-archive-keyring.gpg
sudo curl -fsSL -o /etc/apt/sources.list.d/sysreseval.sources $URL/sysreseval-$dist.sources
sudo apt update &amp;&amp; sudo apt install sysreseval</pre>
HTML
        else
            cat <<HTML
<pre>sudo curl -fsSL -o /etc/apt/sources.list.d/sysreseval.sources $URL/sysreseval-$dist.sources
sudo apt update &amp;&amp; sudo apt install sysreseval</pre>
<p>This repository is not signed: the sources file says <code>Trusted: yes</code>.</p>
HTML
        fi
        echo "<table><tr><th>Package</th><th>Version</th><th>Architecture</th></tr>"
        for p in dists/$dist/main/binary-*/Packages; do
            awk -v RS= -F'\n' '{pkg="";ver="";arch=""; for(i=1;i<=NF;i++){ if($i ~ /^Package: /)pkg=substr($i,10); if($i ~ /^Version: /)ver=substr($i,10); if($i ~ /^Architecture: /)arch=substr($i,15)}; if(pkg!="")print "<tr><td>"pkg"</td><td>"ver"</td><td>"arch"</td></tr>"}' "$p"
        done | sort -u
        echo "</table>"
    done
    if [ "$SIGN" = 1 ]; then
        echo "<p>Signing key: <a href=\"sysreseval-archive-keyring.gpg\">sysreseval-archive-keyring.gpg</a> (<a href=\"sysreseval-archive-keyring.asc\">armored</a>), fingerprint <code>$fpr</code>.</p>"
    fi
    echo "<p>Generated on $(date -u +'%Y-%m-%d %H:%M UTC').</p></body></html>"
} > index.html
echo "apt repository written to $OUT: suites ${dists[*]}$( [ "$SIGN" = 1 ] && echo ", signed with $fpr" || echo ", unsigned")"
