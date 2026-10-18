#!/bin/bash
# Build the Debian packages of SysResEval for one Debian release, in a Docker container of that
# release, and check them by an installation in a second container:
#
#   scripts/build-deb.sh --dist trixie --ref 0.12.0 --test-install   # the release tagged 0.12.0 on GitHub
#   scripts/build-deb.sh --dist forky --local                         # the working tree of this checkout
#
# Packages built, in build/deb/<dist>/ (--out): python3-kathara (the SysResEval fork of Kathara,
# packaging/kathara/), sysreseval and sysreseval-doc (debian/), and on forky python3-fs rebuilt
# from the trixie source package (packaging/python-fs/).  The sources are fetched on this host
# (git or GitHub), the build runs in debian:<dist> (apt-get only), lintian checks the result and
# --test-install installs everything in a fresh debian:<dist> and exercises sre.
#
# Options: --dist trixie|forky (required)   --ref <tag> | --local   --arch amd64|arm64 (the host's)
#          --out <dir>   --test-install   --no-lintian   --no-check (skip the unit tests)
#          --skip-kathara   --skip-fs   --keep (keep the build container's work directory in --out)
set -euo pipefail

die() { echo "build-deb: $*" >&2; exit 1; }
log() { echo; echo "### $*"; }

DIST=""; REF=""; LOCAL=0; ARCH=""; OUT=""; TEST_INSTALL=0; LINTIAN=1; CHECK=1
SKIP_KATHARA=0; SKIP_FS=0; KEEP=0; STAGE=""; UPSTREAM_VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dist) DIST="$2"; shift 2;;
        --ref) REF="$2"; shift 2;;
        --local) LOCAL=1; shift;;
        --arch) ARCH="$2"; shift 2;;
        --out) OUT="$2"; shift 2;;
        --test-install) TEST_INSTALL=1; shift;;
        --no-lintian) LINTIAN=0; shift;;
        --no-check) CHECK=0; shift;;
        --skip-kathara) SKIP_KATHARA=1; shift;;
        --skip-fs) SKIP_FS=1; shift;;
        --keep) KEEP=1; shift;;
        --stage) STAGE="$2"; shift 2;;                 # internal: build | test, run inside the container
        --upstream-version) UPSTREAM_VERSION="$2"; shift 2;;   # internal
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        *) die "unknown option $1 (see --help)";;
    esac
done
[ -n "$DIST" ] || die "--dist trixie|forky is required"
case "$DIST" in trixie|forky|bookworm|sid) ;; *) echo "build-deb: warning: untested distribution $DIST" >&2;; esac

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_PACKAGE=sysreseval
GITHUB_REPOSITORY=sysreseval/sysreseval
# shellcheck source=../packaging/kathara/pin.sh
. "$REPO_DIR/packaging/kathara/pin.sh"
KATHARA_VERSION="${KATHARA_UPSTREAM_VERSION}+git${KATHARA_DATE}.${KATHARA_COMMIT:0:7}"
FS_SOURCE=python-fs
FS_FROM=trixie

# ---------------------------------------------------------------------------------------------
# host side: the sources, then one container per stage
# ---------------------------------------------------------------------------------------------
host_main() {
    [ -n "$REF" ] || [ "$LOCAL" = 1 ] || die "--ref <tag> or --local is required"
    [ -n "$REF" ] && [ "$LOCAL" = 1 ] && die "--ref and --local are exclusive"
    command -v docker >/dev/null || die "docker is not installed"
    docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
    if [ -z "$ARCH" ]; then
        case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die "unsupported architecture $(uname -m)";; esac
    fi
    OUT="${OUT:-$REPO_DIR/build/deb}"
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
    local dist_out="$OUT/$DIST" sources="$OUT/$DIST/sources"
    # the previous output goes, except the packages a --skip-* option keeps (installed by the build)
    rm -rf "$sources" "$dist_out/sysreseval" "$dist_out/work" "$dist_out"/*.log "$dist_out/lintian.txt"
    [ "$SKIP_KATHARA" = 1 ] || rm -rf "$dist_out/kathara"
    [ "$SKIP_FS" = 1 ] || rm -rf "$dist_out/python-fs"
    mkdir -p "$sources"

    log "sources of $SRC_PACKAGE"
    if [ -n "$REF" ]; then
        UPSTREAM_VERSION="${REF#v}"
        local url="https://codeload.github.com/$GITHUB_REPOSITORY/tar.gz/refs/tags/$REF"
        echo "downloading $url"
        curl -fsSL -o "$sources/${SRC_PACKAGE}_${UPSTREAM_VERSION}.orig.tar.gz" "$url" || die "cannot download the tag $REF"
        local tarball="$sources/${SRC_PACKAGE}_${UPSTREAM_VERSION}.orig.tar.gz" in_tarball
        in_tarball=$(tar -xzOf "$tarball" "$(tar -tzf "$tarball" | grep '/src/SRE/params.py$' | head -1)" \
                     | sed -n 's/^sre_version = "\(.*\)".*/\1/p')
        if [ "$in_tarball" != "$UPSTREAM_VERSION" ]; then
            echo "build-deb: warning: sre_version is \"$in_tarball\" in the tag $REF: the package says $UPSTREAM_VERSION" >&2
        fi
    else
        local last_tag sha date
        last_tag=$(git -C "$REPO_DIR" describe --tags --abbrev=0 2>/dev/null || echo 0.0)
        sha=$(git -C "$REPO_DIR" rev-parse --short=7 HEAD)
        date=$(date -u +%Y%m%d)
        UPSTREAM_VERSION="${last_tag#v}+git${date}.${sha}"
        if [ -n "$(git -C "$REPO_DIR" status --porcelain --untracked-files=no)" ]; then
            echo "build-deb: warning: the working tree has uncommitted changes (they are packaged)" >&2
        fi
        echo "packaging the working tree as $UPSTREAM_VERSION"
        # the tracked files and the untracked ones git does not ignore, under one top directory
        # (python3 rather than tar: GNU and BSD tar differ on --transform)
        git -C "$REPO_DIR" ls-files -z --cached --others --exclude-standard > "$sources/.files"
        python3 -I -c '
import os, sys, tarfile
root, prefix, out, listing = sys.argv[1:5]
names = [n for n in open(listing, "rb").read().decode().split("\0") if n]
with tarfile.open(out, "w:gz") as tar:
    for name in names:
        path = os.path.join(root, name)
        if os.path.exists(path) or os.path.islink(path):
            tar.add(path, arcname=f"{prefix}/{name}", recursive=False)
' "$REPO_DIR" "${SRC_PACKAGE}-${UPSTREAM_VERSION}" "$sources/${SRC_PACKAGE}_${UPSTREAM_VERSION}.orig.tar.gz" "$sources/.files"
        rm -f "$sources/.files"
    fi
    if [ "$SKIP_KATHARA" = 0 ]; then
        log "sources of kathara ($KATHARA_VERSION)"
        local kurl="https://codeload.github.com/$KATHARA_REPOSITORY/tar.gz/$KATHARA_COMMIT"
        echo "downloading $kurl"
        curl -fsSL -o "$sources/kathara_${KATHARA_VERSION}.orig.tar.gz" "$kurl" || die "cannot download the Kathara fork"
    fi

    log "build in debian:$DIST ($ARCH)"
    local opts=(--stage build --dist "$DIST" --upstream-version "$UPSTREAM_VERSION")
    [ "$LINTIAN" = 1 ] || opts+=(--no-lintian)
    [ "$CHECK" = 1 ] || opts+=(--no-check)
    [ "$SKIP_KATHARA" = 0 ] || opts+=(--skip-kathara)
    [ "$SKIP_FS" = 0 ] || opts+=(--skip-fs)
    [ "$KEEP" = 0 ] || opts+=(--keep)
    docker run --rm --platform "linux/$ARCH" -e DEBIAN_FRONTEND=noninteractive \
        -v "$REPO_DIR:/src:ro" -v "$OUT:/out" "debian:$DIST" \
        bash /src/scripts/build-deb.sh "${opts[@]}" 2>&1 | tee "$dist_out/build.log"
    [ "${PIPESTATUS[0]}" = 0 ] || die "the build failed (see $dist_out/build.log)"

    if [ "$TEST_INSTALL" = 1 ]; then
        log "installation test in a fresh debian:$DIST ($ARCH)"
        # SYS_PTRACE: root reads /proc/<pid>/exe of the sudo and sre-wrapper processes of a student
        # (the ancestry check of sre), which root does on a host but not in a default container
        docker run --rm --platform "linux/$ARCH" -e DEBIAN_FRONTEND=noninteractive --cap-add SYS_PTRACE \
            -v "$REPO_DIR:/src:ro" -v "$OUT:/out" "debian:$DIST" \
            bash /src/scripts/build-deb.sh --stage test --dist "$DIST" --upstream-version "$UPSTREAM_VERSION" \
            2>&1 | tee "$dist_out/test-install.log"
        [ "${PIPESTATUS[0]}" = 0 ] || die "the installation test failed (see $dist_out/test-install.log)"
    fi
    log "done: $dist_out"
    find "$dist_out" -name '*.deb' | sort
}

# ---------------------------------------------------------------------------------------------
# inside the build container: /src is the checkout (read-only), /out/<dist> the output
# ---------------------------------------------------------------------------------------------
apt_install() { apt-get install -y --no-install-recommends "$@"; }

build_one() {
    # build_one <name> <source dir> <output subdir>: build-deps, dpkg-buildpackage, artefacts
    local name="$1" dir="$2" sub="$3"
    (
        cd "$dir"
        mk-build-deps -i -r -t 'apt-get -y --no-install-recommends' debian/control
        dpkg-buildpackage -us -uc -b
    )
    mkdir -p "/out/$DIST/$sub"
    # the artefacts of this build only (every other build has its own parent directory)
    cp "$(dirname "$dir")"/*.deb "$(dirname "$dir")"/*.changes "$(dirname "$dir")"/*.buildinfo "/out/$DIST/$sub/"
    echo "built $name: $(ls "/out/$DIST/$sub"/*.deb | xargs -n1 basename | tr '\n' ' ')"
}

build_main() {
    [ -n "$UPSTREAM_VERSION" ] || die "internal: --upstream-version missing"
    local sources="/out/$DIST/sources" work=/build
    mkdir -p "$work"
    # the identity of the changelog entries dch and mk-build-deps add (from the maintainer of debian/changelog)
    DEBFULLNAME=$(sed -n 's/^ -- \(.*\) <.*>  .*/\1/p' /src/debian/changelog | head -1)
    DEBEMAIL=$(sed -n 's/^ -- .*<\(.*\)>  .*/\1/p' /src/debian/changelog | head -1)
    export DEBFULLNAME DEBEMAIL
    log "build tools"
    apt-get update
    apt_install build-essential devscripts debhelper dh-python equivs lintian fakeroot quilt ca-certificates

    if [ "$DIST" != "$FS_FROM" ] && [ "$SKIP_FS" = 0 ]; then
        if apt-cache show python3-fs >/dev/null 2>&1; then
            echo "python3-fs exists in $DIST: no rebuild"
        else
            log "python3-fs: rebuild of the $FS_FROM source package for $DIST"
            echo "deb-src http://deb.debian.org/debian $FS_FROM main" > /etc/apt/sources.list.d/build-deb-$FS_FROM-src.list
            apt-get update
            mkdir -p "$work/fs"
            (cd "$work/fs" && apt-get source --only-source "$FS_SOURCE/$FS_FROM")
            local fsdir
            fsdir=$(find "$work/fs" -maxdepth 1 -mindepth 1 -type d | head -1)
            # the extra patches of packaging/python-fs/patches/: appended to the series and applied
            # now (apt-get source applied Debian's own, which dpkg-buildpackage then takes as done)
            for p in /src/packaging/python-fs/patches/*.patch; do
                [ -f "$p" ] || continue
                echo "python-fs: adding $(basename "$p")"
                cp "$p" "$fsdir/debian/patches/"
                basename "$p" >> "$fsdir/debian/patches/series"
            done
            (cd "$fsdir" && QUILT_PATCHES=debian/patches quilt push -a)
            (cd "$fsdir" && dch --local "~$DIST" --distribution "$DIST" --force-distribution \
                "Rebuild of the $FS_FROM package for $DIST (SysResEval).")
            # the unit tests of fs fail with Python 3.14 (#1123243); the package is otherwise fine
            DEB_BUILD_OPTIONS=nocheck build_one python-fs "$fsdir" python-fs
            apt_install "/out/$DIST/python-fs/python3-fs_"*.deb
        fi
    fi

    if [ "$SKIP_FS" = 1 ] && ls "/out/$DIST/python-fs/python3-fs_"*.deb >/dev/null 2>&1; then
        apt_install "/out/$DIST/python-fs/python3-fs_"*.deb       # built by a previous run
    fi
    if [ "$SKIP_KATHARA" = 0 ]; then
        log "python3-kathara $KATHARA_VERSION"
        mkdir -p "$work/kathara"
        cp "$sources/kathara_${KATHARA_VERSION}.orig.tar.gz" "$work/kathara/"
        tar -xzf "$work/kathara/kathara_${KATHARA_VERSION}.orig.tar.gz" -C "$work/kathara"
        local kdir
        kdir=$(find "$work/kathara" -maxdepth 1 -mindepth 1 -type d | head -1)
        [ "$kdir" = "$work/kathara/kathara-$KATHARA_VERSION" ] || mv "$kdir" "$work/kathara/kathara-$KATHARA_VERSION"
        kdir="$work/kathara/kathara-$KATHARA_VERSION"
        cp -a /src/packaging/kathara/debian "$kdir/debian"
        (cd "$kdir" && dch --local "~$DIST" --distribution "$DIST" --force-distribution "Build for $DIST.")
        build_one kathara "$kdir" kathara
        # installs the fresh package with its dependencies: an unmapped Python requirement fails here
        apt_install "/out/$DIST/kathara/python3-kathara_"*.deb
    elif ls "/out/$DIST/kathara/python3-kathara_"*.deb >/dev/null 2>&1; then
        apt_install "/out/$DIST/kathara/python3-kathara_"*.deb     # built by a previous run
    fi

    log "$SRC_PACKAGE $UPSTREAM_VERSION"
    mkdir -p "$work/sysreseval"
    cp "$sources/${SRC_PACKAGE}_${UPSTREAM_VERSION}.orig.tar.gz" "$work/sysreseval/"
    tar -xzf "$work/sysreseval/${SRC_PACKAGE}_${UPSTREAM_VERSION}.orig.tar.gz" -C "$work/sysreseval"
    local sdir
    sdir=$(find "$work/sysreseval" -maxdepth 1 -mindepth 1 -type d | head -1)
    [ "$sdir" = "$work/sysreseval/${SRC_PACKAGE}-${UPSTREAM_VERSION}" ] \
        || mv "$sdir" "$work/sysreseval/${SRC_PACKAGE}-${UPSTREAM_VERSION}"
    sdir="$work/sysreseval/${SRC_PACKAGE}-${UPSTREAM_VERSION}"
    rm -rf "$sdir/debian"
    cp -a /src/debian "$sdir/debian"
    (
        cd "$sdir"
        local current
        current=$(dpkg-parsechangelog -S Version | sed 's/-[^-]*$//')
        if [ "$current" = "$UPSTREAM_VERSION" ]; then
            dch --local "~$DIST" --distribution "$DIST" --force-distribution "Build for $DIST."
        else
            dch --newversion "${UPSTREAM_VERSION}-1~${DIST}1" --distribution "$DIST" --force-distribution \
                --force-bad-version "Build of $UPSTREAM_VERSION for $DIST."
        fi
    )
    if [ "$CHECK" = 1 ]; then
        build_one "$SRC_PACKAGE" "$sdir" sysreseval
    else
        DEB_BUILD_OPTIONS=nocheck build_one "$SRC_PACKAGE" "$sdir" sysreseval
    fi

    if [ "$LINTIAN" = 1 ]; then
        log "lintian"
        set +e
        lintian --no-tag-display-limit --info --fail-on error "/out/$DIST/sysreseval/"*.changes "/out/$DIST/kathara/"*.changes 2>&1 \
            | tee "/out/$DIST/lintian.txt"
        local status=${PIPESTATUS[0]}
        set -e
        [ "$status" = 0 ] || die "lintian reported errors (see lintian.txt)"
    fi
    if [ "$KEEP" = 1 ]; then
        rm -rf "/out/$DIST/work"
        cp -a "$work" "/out/$DIST/work"
    fi
}

# ---------------------------------------------------------------------------------------------
# inside the test container: install the packages, run sre
# ---------------------------------------------------------------------------------------------
failures=0
check() {
    # check <description> <command...>: run, report, count the failures
    local desc="$1"; shift
    if "$@" >/tmp/check.out 2>&1; then
        echo "ok      $desc"
    else
        echo "FAILED  $desc"
        sed 's/^/        /' /tmp/check.out | tail -20
        failures=$((failures + 1))
    fi
}

test_main() {
    log "installation of the packages"
    apt-get update
    apt_install ca-certificates
    local debs=()
    for f in "/out/$DIST/python-fs/"python3-fs_*.deb "/out/$DIST/kathara/"python3-kathara_*.deb \
             "/out/$DIST/sysreseval/"sysreseval_*.deb "/out/$DIST/sysreseval/"sysreseval-doc_*.deb; do
        [ -f "$f" ] && debs+=("$f")
    done
    apt_install "${debs[@]}"

    log "checks"
    export LOGNAME=root     # what a login shell sets: the username of a command run by root
    check "the sre user exists" id sre
    check "sre is in the docker group" sh -c 'id -nG sre | tr " " "\n" | grep -qx docker'
    check "/var/lib/sre/lab/sre links the shipped labs" test -L /var/lib/sre/lab/sre
    check "/var/lib/sre/home exists" test -d /var/lib/sre/home
    check "lib/ is sre-only (sre:550)" sh -c 'test "$(stat -c %U:%a /usr/lib/sysreseval/lib)" = sre:550'
    check "shipped labs are sre-only (sre:550)" sh -c 'test "$(stat -c %U:%a /usr/share/sysreseval/lab/sre)" = sre:550'
    check "exetests.py is executable" test -x /usr/lib/sysreseval/lib/exetests.py
    check "the sudoers file passes visudo" visudo -cqf /etc/sudoers.d/sysreseval
    check "sre --version prints $UPSTREAM_VERSION" sh -c "sre --version | grep -qF '$UPSTREAM_VERSION'"
    check "params: fhs layout, ids by name, no self update" python3 -c "
import sys, pwd; sys.path.insert(0, '/usr/lib/sysreseval')
import SRE.params as p
assert p.install_layout == 'fhs', p.install_layout
assert p.lab_dir == '/var/lib/sre/lab' and p.shipped_lab_dir == '/usr/share/sysreseval/lab', (p.lab_dir, p.shipped_lab_dir)
assert p.sre_uid == pwd.getpwnam('sre').pw_uid and p.sre_gid == pwd.getpwnam('sre').pw_gid
assert p.sre_wrapper == '/usr/bin/sre-wrapper' and p.sre_exe == '/usr/sbin/sre'
assert p.sre_user_public_dir == '/var/lib/sre/home'
assert p.fontdir == '/usr/share/fonts/truetype/dejavu' and p.site_params_file == '/etc/sysreseval/params.py'
assert not p.self_update_allowed
assert '/usr/share/sysreseval/lab' in p.authorized_src_dir
"
    check "the fonts of the PDFs are installed" sh -c 'ls /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf /usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'
    check "the neato layout engine of graphviz works" sh -c 'echo "graph { a -- b }" | neato -Tsvg >/dev/null'
    check "import of SRE.lib_sre (the real Kathara)" python3 -c "import sys; sys.path.insert(0, '/usr/lib/sysreseval'); import SRE.lib_sre"
    check "import of the GUI (offscreen)" env QT_QPA_PLATFORM=offscreen python3 -c "import sys; sys.path.insert(0, '/usr/lib/sysreseval'); import sysreseval.main_window"
    check "sre list shows the shipped labs" sh -c 'sre list | grep -q "sre/dhcp.py"'
    check "sre check of a shipped lab through the link" sre check /var/lib/sre/lab/sre/dhcp.py
    check "sre update is refused" sh -c '! sre update --check 2>/tmp/upd.err; grep -q apt /tmp/upd.err'
    check "a student runs sre through sre-wrapper" sh -c 'id student >/dev/null 2>&1 || useradd -m student; su student -c "sre-wrapper list" | grep -q "sre/dhcp.py"'
    check "the completion file is installed" test -f /usr/share/bash-completion/completions/sre
    check "the desktop file is installed" test -f /usr/share/applications/sysreseval.desktop
    check "the network plugin script is installed" test -x /usr/sbin/sysreseval-network-plugin
    check "the documentation is installed" test -f /usr/share/doc/sysreseval/html/main/index.html

    log "removal"
    # the data of the site (here an archive and a lab) stay after the purge, the link goes
    mkdir -p /var/lib/sre/archives /var/lib/sre/lab/site
    touch /var/lib/sre/archives/keep.zst /var/lib/sre/lab/site/keep.py
    check "apt purge sysreseval" apt-get purge -y sysreseval
    check "the archives are kept after the purge" test -f /var/lib/sre/archives/keep.zst
    check "the site's labs are kept after the purge" test -f /var/lib/sre/lab/site/keep.py
    check "the labs link is removed by the purge" sh -c '! test -e /var/lib/sre/lab/sre'
    check "the sre user is kept after the purge" id sre
    check "/etc/sysreseval is removed by the purge" sh -c '! test -e /etc/sysreseval'

    echo
    if [ "$failures" = 0 ]; then
        echo "installation test: every check passed"
    else
        echo "installation test: $failures check(s) failed"
        exit 1
    fi
}

case "$STAGE" in
    "") host_main;;
    build) build_main;;
    test) test_main;;
    *) die "unknown stage $STAGE";;
esac
