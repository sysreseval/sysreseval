#!/bin/bash
# Release SysResEval:
#
#   scripts/release.sh <version> [-m NOTES | --notes-file FILE]     e.g. scripts/release.sh 0.13.2
#                                                                   (make release VERSION=0.13.2)
#   0. shows the current and the new version and asks for a confirmation; uncommitted changes are
#      listed and confirmed too (those of params.py and debian/changelog go into the release
#      commit, the rest stays out: leftover work is fine); -y / --yes skips both questions.
#      The release notes (one item per line, "- " markers optional, an indented line continues
#      the previous one) come from -m / --notes (repeatable), --notes-file, or are asked on the terminal (an empty line ends them,
#      nothing = the notes GitHub generates from the commits only): they become the bullets of the
#      debian/changelog entry, the body of the release commit and tag, and the top of the GitHub
#      release notes, above the generated list of commits
#   1. sre_version = "<version>" in src/SRE/params.py and a <version>-1 entry in debian/changelog
#   2. make tests (--no-check skips it)
#   3. commit "Release <version>", tag <version>, push main and the tag to the upstream remote
#   4. the GitHub release of the tag (gh release create, notes generated from the commits)
#   5. wait for the "release" workflow (the trixie and forky packages, attached to the release)
#      and for the "pages" workflow (the documentation and the apt repository on GitHub Pages);
#      --no-wait returns right after the release is created.  A run that stopped after the
#      tag was made (push or GitHub unreachable) is resumed by running the same command again
#
#   scripts/release.sh --setup              once: the signing key of the apt repository (generated
#      with gpg in your keyring, or in a debian container without gpg) stored as the repository
#      secret APT_SIGNING_KEY, and GitHub Pages switched to the Actions deployment of
#      .github/workflows/pages.yml.  An existing secret is kept (--replace-key uploads the key of
#      your keyring again: the workflow signs unattended, so a passphrase-protected key is copied
#      without its passphrase into the secret, the keyring copy keeps it)
#
# Needs git, gh (logged in), python3 and make; nothing is built here: the packages are built by
# .github/workflows/release.yml.  Helpers of the tests: --compare A B (exit 0 when B is a greater
# version than A), --changelog-entry V [-m NOTES] (prints the entry that would be added to
# debian/changelog).
set -euo pipefail

die() { echo "release: $*" >&2; exit 1; }
log() { echo; echo "### $*"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARAMS="$REPO_DIR/src/SRE/params.py"
CHANGELOG="$REPO_DIR/debian/changelog"
SECRET_NAME=APT_SIGNING_KEY
KEY_UID_NAME="SysResEval APT repository"
KEY_FILE="$HOME/.config/sysreseval/apt-signing-key.asc"
RELEASE_WORKFLOW=release.yml
PAGES_WORKFLOW=pages.yml

# --- helpers -------------------------------------------------------------------------------------
version_gt() {     # version_gt A B: B is a greater version than A
    python3 -c '
import sys
a, b = (tuple(int(x) for x in v.split(".")) for v in sys.argv[1:3])
sys.exit(0 if b > a else 1)' "$1" "$2"
}

current_version() { sed -n 's/^sre_version = "\([^"]*\)".*/\1/p' "$PARAMS" | head -1; }

maintainer() {     # the maintainer of the last changelog entry: "Name <email>"
    sed -n 's/^ -- \(.*>\)  .*/\1/p' "$CHANGELOG" | head -1
}

changelog_entry() {      # changelog_entry VERSION [NOTES]: the entry; the notes' paragraphs and list items are its bullets
    printf 'sysreseval (%s-1) unstable; urgency=medium\n\n' "$1"
    if [ -n "${2:-}" ]; then
        # one item per line ("- " / "* " markers dropped), an indented line continues the previous item
        NOTES="$2" python3 -c '
import os, re
items = []
for line in os.environ["NOTES"].splitlines():
    if not line.strip():
        continue
    if line[0] in " \t" and items:
        items[-1] += " " + line.strip()
    else:
        items.append(re.sub(r"^[-*+] +", "", line.strip()))
for item in items:
    words, lines, width = item.split(), [], 76
    for word in words:
        if lines and len(lines[-1]) + 1 + len(word) <= width: lines[-1] += " " + word
        else: lines.append(word)
    print("  * " + lines[0])
    for extra in lines[1:]: print("    " + extra)
'
    else
        printf '  * Release %s.\n' "$1"
    fi
    printf '\n -- %s  %s\n' "$(maintainer)" "$(date -R)"
}

read_notes() {           # the release notes typed on the terminal, an empty line ends them
    local line notes=""
    # (called in a command substitution: everything meant for the eyes goes to stderr)
    echo "Release notes: one item per line, an empty line ends them (nothing: only the notes GitHub" >&2
    echo "generates from the commits). They go to debian/changelog, the commit and the release page." >&2
    while IFS= read -r -p "note> " line; do
        [ -n "$line" ] || break
        notes="${notes:+$notes
}$line"
    done
    printf '%s' "$notes"
}

github_repo() {    # owner/name from the url of the upstream remote (an ssh alias is fine)
    local remote url
    remote=$(git -C "$REPO_DIR" rev-parse --abbrev-ref --symbolic-full-name main@{upstream} 2>/dev/null) \
        || die "main has no upstream branch"
    remote="${remote%%/*}"
    url=$(git -C "$REPO_DIR" remote get-url "$remote")
    url="${url%/}"; url="${url%.git}"               # git@host:owner/name.git, https://host/owner/name
    local name="${url##*/}" rest="${url%/*}"
    local owner="${rest##*[:/]}"
    [ -n "$owner" ] && [ -n "$name" ] || die "cannot read owner/name from the remote url $url"
    echo "$owner/$name"
}

upstream_remote() {
    local remote
    remote=$(git -C "$REPO_DIR" rev-parse --abbrev-ref --symbolic-full-name main@{upstream})
    echo "${remote%%/*}"
}

wait_run() {       # wait_run <workflow file> <jq filter on a run> <label>: find the run (2 min) and watch it
    local workflow="$1" filter="$2" label="$3" id="" i
    for i in $(seq 1 24); do
        id=$(gh run list --repo "$GH_REPO" --workflow "$workflow" --limit 20 \
                 --json databaseId,headBranch,event,status,createdAt --jq "$filter" | head -1)
        [ -n "$id" ] && break
        sleep 5
    done
    [ -n "$id" ] || die "no run of $workflow for $label appeared within 2 minutes (see gh run list)"
    echo "run $id of $workflow: https://github.com/$GH_REPO/actions/runs/$id"
    gh run watch "$id" --repo "$GH_REPO" --exit-status --interval 15 >/dev/null \
        || die "the $workflow run of $label failed: https://github.com/$GH_REPO/actions/runs/$id"
    echo "$workflow: success"
}

# --- setup: the signing key and GitHub Pages ------------------------------------------------------
# key_signs_unattended KEY: the armored private key signs in batch mode without any passphrase
key_signs_unattended() {
    local home
    home=$(mktemp -d)
    chmod 700 "$home"
    ( printf '%s\n' "$1" | GNUPGHOME="$home" gpg --batch --quiet --import 2>/dev/null \
      && echo x | GNUPGHOME="$home" gpg --batch --pinentry-mode error --detach-sign >/dev/null 2>&1 )
    local status=$?
    rm -rf "$home"
    return $status
}

# unprotected_copy FPR: the key FPR of the keyring exported without its passphrase, through a
# temporary keyring where the passphrase is removed (interactive: the current one is asked, then
# an empty new one twice); the keyring copy is untouched
unprotected_copy() {
    local home
    home=$(mktemp -d)
    chmod 700 "$home"
    echo "the key $1 is passphrase-protected in your keyring: making the unprotected copy the workflow needs" >&2
    echo "(enter its passphrase, then leave the new one empty twice and confirm)" >&2
    gpg --batch --export-secret-keys "$1" | GNUPGHOME="$home" gpg --batch --quiet --import 2>/dev/null
    GNUPGHOME="$home" gpg --change-passphrase "$1" >&2 || { rm -rf "$home"; die "the passphrase was not removed"; }
    GNUPGHOME="$home" gpg --batch --armor --export-secret-keys "$1"
    rm -rf "$home"
}

setup() {
    local email key fpr pages_url
    email=$(maintainer | sed -n 's/.*<\(.*\)>.*/\1/p')
    [ -n "$email" ] || die "no maintainer email in $CHANGELOG"
    GH_REPO=$(github_repo)
    gh auth status >/dev/null 2>&1 || die "gh is not logged in (gh auth login)"

    log "signing key of the apt repository"
    if [ "$REPLACE_KEY" = 0 ] && gh secret list --repo "$GH_REPO" --json name --jq '.[].name' | grep -qx "$SECRET_NAME"; then
        echo "secret $SECRET_NAME exists on $GH_REPO: kept (--replace-key uploads the key of your keyring again)"
    elif command -v gpg >/dev/null; then
        # (gpg exits 2 when no key matches: not an error here)
        fpr=$( (gpg --batch --with-colons --list-secret-keys "=$KEY_UID_NAME <$email>" 2>/dev/null || true) \
              | awk -F: '/^fpr/ {print $10; exit}')
        if [ -n "$fpr" ]; then
            echo "key $fpr ($KEY_UID_NAME <$email>) already in your keyring: reused"
        else
            echo "generating an RSA 4096 key $KEY_UID_NAME <$email> in your keyring (no passphrase, no expiry)"
            gpg --batch --quiet --gen-key <<GEN
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: $KEY_UID_NAME
Name-Email: $email
Expire-Date: 0
%commit
GEN
            fpr=$( (gpg --batch --with-colons --list-secret-keys "=$KEY_UID_NAME <$email>" 2>/dev/null || true) \
                  | awk -F: '/^fpr/ {print $10; exit}')
            [ -n "$fpr" ] || die "the key was not generated"
            echo "key $fpr generated; back up your keyring (gpg --export-secret-keys $fpr)"
        fi
        key=$(gpg --batch --pinentry-mode error --armor --export-secret-keys "$fpr" 2>/dev/null || true)
        if [ -z "$key" ] || ! key_signs_unattended "$key"; then
            key=$(unprotected_copy "$fpr")
            key_signs_unattended "$key" || die "the exported key still needs a passphrase"
        fi
    else
        if [ -f "$KEY_FILE" ]; then
            echo "gpg is not installed: the key of $KEY_FILE is reused"
        else
            command -v docker >/dev/null || die "neither gpg nor docker is available to generate the key"
            echo "gpg is not installed: generating the key in a debian container, kept in $KEY_FILE"
            mkdir -p "$(dirname "$KEY_FILE")"
            docker run --rm -i -e NAME="$KEY_UID_NAME" -e EMAIL="$email" debian:trixie bash -s > "$KEY_FILE.tmp" <<'GEN'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null 2>&1 && apt-get install -y -q --no-install-recommends gnupg >/dev/null 2>&1
export GNUPGHOME=$(mktemp -d)
gpg --batch --quiet --gen-key <<EOF2
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: $NAME
Name-Email: $EMAIL
Expire-Date: 0
%commit
EOF2
gpg --batch --armor --export-secret-keys
GEN
            grep -q 'BEGIN PGP PRIVATE KEY BLOCK' "$KEY_FILE.tmp" || { rm -f "$KEY_FILE.tmp"; die "the key was not generated"; }
            mv "$KEY_FILE.tmp" "$KEY_FILE"
            chmod 600 "$KEY_FILE"
        fi
        key=$(cat "$KEY_FILE")
    fi
    if [ -n "${key:-}" ]; then
        printf '%s\n' "$key" | gh secret set "$SECRET_NAME" --repo "$GH_REPO"
        echo "secret $SECRET_NAME set on $GH_REPO (the pages workflow signs the repository with it)"
    fi

    log "GitHub Pages: deployment by the pages workflow"
    if gh api "repos/$GH_REPO/pages" >/dev/null 2>&1; then
        gh api -X PUT "repos/$GH_REPO/pages" -f build_type=workflow >/dev/null
    else
        gh api -X POST "repos/$GH_REPO/pages" -f build_type=workflow >/dev/null
    fi
    pages_url=$(gh api "repos/$GH_REPO/pages" --jq .html_url)
    echo "Pages of $GH_REPO deployed by .github/workflows/$PAGES_WORKFLOW at $pages_url"
    echo
    echo "Next: scripts/release.sh <version>, or 'gh workflow run $PAGES_WORKFLOW --repo $GH_REPO' to publish"
    echo "      the documentation and the packages of the existing releases right away."
}

# --- the release ---------------------------------------------------------------------------------
release() {
    local version="$1" check="$2" wait="$3" yes="$4" notes="$5" current remote dirty dirty_release_files release_url started_at answer
    local resume="" remote_tag same_version=0
    started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    [[ "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "version '$version' is not of the form 0.13.2"
    current=$(current_version)
    [ -n "$current" ] || die "no sre_version line in $PARAMS"
    if [ "$current" = "$version" ]; then
        same_version=1       # a previous run bumped the tree: the checks below say where to resume
    else
        version_gt "$current" "$version" || die "version $version is not greater than the current $current"
    fi
    # nothing before the confirmation
    echo "SysResEval: current version $current, new release $version"
    echo "  $version will be written to src/SRE/params.py and debian/changelog, committed, tagged,"
    echo "  pushed to the upstream remote and published as a GitHub release (then packaged)."
    if [ "$yes" != 1 ]; then
        [ -t 0 ] || die "stdin is not a terminal: use --yes to confirm the version $version"
        read -r -p "Is the version $version correct? [y/N] " answer
        case "$answer" in y|Y|yes|YES|Yes) ;; *) echo "release: aborted, nothing done"; exit 1;; esac
    fi
    cd "$REPO_DIR"
    [ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on the main branch"
    grep -qE '^debug_mode[[:space:]]*=[[:space:]]*True' "$PARAMS" && die "debug_mode is True in src/SRE/params.py: not releasable"
    # uncommitted changes: the two files of the bump are committed as they are (their changes go
    # into the release commit), everything else is left out; leftover work is allowed, once seen
    dirty_release_files=$(git status --porcelain -- "$PARAMS" "$CHANGELOG")
    dirty=$(git status --porcelain --untracked-files=normal | grep -v '^.. \(src/SRE/params.py\|debian/changelog\)$' || true)
    if [ -n "$dirty_release_files" ] || [ -n "$dirty" ]; then
        echo "release: the tree has uncommitted changes:"
        if [ -n "$dirty_release_files" ]; then
            echo "  committed with the release (the files the release edits):"
            echo "$dirty_release_files" | sed 's/^/    /'
        fi
        if [ -n "$dirty" ]; then
            echo "  left out of the release (neither committed nor released):"
            echo "$dirty" | sed 's/^/    /'
        fi
        if [ "$yes" != 1 ]; then
            read -r -p "Release $version with these leftovers? [y/N] " answer
            case "$answer" in y|Y|yes|YES|Yes) ;; *) echo "release: aborted, nothing done"; exit 1;; esac
        fi
    fi
    if [ -z "$notes" ] && [ "$yes" != 1 ]; then
        notes=$(read_notes)
    fi
    command -v gh >/dev/null || die "gh is not installed"
    gh auth status >/dev/null 2>&1 || die "gh is not logged in (gh auth login)"
    GH_REPO=$(github_repo)
    remote=$(upstream_remote)
    log "checks against $remote ($GH_REPO)"
    git fetch --quiet "$remote" main --tags
    if [ "$(git rev-list --count "HEAD..$remote/main")" != 0 ]; then
        die "main is behind $remote/main: pull first"
    fi
    if gh release view "$version" --repo "$GH_REPO" >/dev/null 2>&1; then
        die "the release $version exists on GitHub"
    fi
    # a previous run may have stopped after the tag (push or GitHub unreachable...): go on from there
    remote_tag=$(git ls-remote --tags "$remote" "refs/tags/$version^{}" "refs/tags/$version" | awk '{print $1}' | tail -1)
    if [ -n "$remote_tag" ]; then
        [ "$remote_tag" = "$(git rev-parse HEAD)" ] || die "the tag $version exists on $remote and is not HEAD"
        [ "$same_version" = 1 ] || die "the tag $version exists on $remote but sre_version is $current"
        resume=release
        echo "the tag $version is on $remote at HEAD without a release: resuming at the GitHub release"
    elif git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
        [ "$(git rev-parse "refs/tags/$version^{}")" = "$(git rev-parse HEAD)" ] && [ "$same_version" = 1 ] \
            || die "the tag $version exists locally and is not the release of HEAD (git tag -d $version)"
        resume=push
        echo "the tag $version is at HEAD and not on $remote: resuming at the push"
    elif [ "$same_version" = 1 ]; then
        die "sre_version is already $version in the tree but no tag $version exists: set it back or tag by hand"
    else
        echo "current version $current, releasing $version on $remote/main"
    fi

    if [ -z "$resume" ]; then
    log "version bump"
    python3 - "$PARAMS" "$version" <<'PY'
import re, sys
path, version = sys.argv[1:3]
text = open(path).read()
lines = re.findall(r'^sre_version = .*$', text, re.M)
assert len(lines) == 1, lines
open(path, 'w').write(text.replace(lines[0], f'sre_version = "{version}"'))
PY
    { changelog_entry "$version" "$notes"; echo; cat "$CHANGELOG"; } > "$CHANGELOG.new"
    mv "$CHANGELOG.new" "$CHANGELOG"
    echo "sre_version = \"$version\", debian/changelog:"
    sed -n '1,/^ -- /p' "$CHANGELOG" | sed 's/^/    /'

    if [ "$check" = 1 ]; then
        log "make tests"
        make -s -C "$REPO_DIR" tests > "$REPO_DIR/build/release-tests.log" 2>&1 \
            || { tail -20 "$REPO_DIR/build/release-tests.log"; die "the tests fail (build/release-tests.log): nothing committed, the version bump is left in the tree"; }
        tail -1 "$REPO_DIR/build/release-tests.log"
    fi

    log "commit, tag, push"
    git add -- "$PARAMS" "$CHANGELOG"
    if [ -n "$notes" ]; then
        git commit -q -m "Release $version" -m "$notes"
        git tag -a "$version" -m "Release $version" -m "$notes"
    else
        git commit -q -m "Release $version"
        git tag -a "$version" -m "Release $version"
    fi
    fi
    if [ "$resume" != release ]; then
    git push -q "$remote" main "refs/tags/$version"
    echo "pushed $(git rev-parse --short HEAD) and the tag $version to $remote"
    fi

    log "GitHub release $version"
    # the given notes come first, the notes gh generates from the commits follow (after one newline:
    # the trailing one here makes it a blank line before their "What's Changed" heading)
    if [ -n "$notes" ]; then
        release_url=$(gh release create "$version" --repo "$GH_REPO" --verify-tag --title "$version" --generate-notes --notes "$notes"$'\n')
    else
        release_url=$(gh release create "$version" --repo "$GH_REPO" --verify-tag --title "$version" --generate-notes)
    fi
    echo "$release_url"

    if [ "$wait" = 1 ]; then
        log "packages (release workflow)"
        wait_run "$RELEASE_WORKFLOW" ".[] | select(.headBranch == \"$version\") | .databaseId" "$version"
        log "documentation and apt repository (pages workflow)"
        wait_run "$PAGES_WORKFLOW" ".[] | select(.event == \"workflow_run\" and .createdAt >= \"$started_at\") | .databaseId" "$version"
        echo
        echo "release: $release_url"
        echo "apt repository: $(gh api "repos/$GH_REPO/pages" --jq .html_url 2>/dev/null || echo "(GitHub Pages)")apt/"
    else
        echo "the release and pages workflows are running: gh run list --repo $GH_REPO"
    fi
}

# --- command line ----------------------------------------------------------------------------------
VERSION=""; CHECK=1; WAIT=1; YES=0; REPLACE_KEY=0; NOTES=""; MODE=release; ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --setup) MODE=setup; shift;;
        --replace-key) REPLACE_KEY=1; shift;;
        --no-check) CHECK=0; shift;;
        --no-wait) WAIT=0; shift;;
        -y|--yes) YES=1; shift;;
        -m|--notes) [ $# -ge 2 ] || die "$1 needs a text"; NOTES="${NOTES:+$NOTES

}$2"; shift 2;;
        --notes-file) [ $# -ge 2 ] && [ -f "$2" ] || die "--notes-file needs a readable file"; NOTES="$(cat "$2")"; shift 2;;
        --compare) MODE=compare; ARGS=("$2" "$3"); shift 3;;
        --changelog-entry) MODE=changelog; ARGS=("$2"); shift 2;;
        -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        -*) die "unknown option $1 (see --help)";;
        *) [ -z "$VERSION" ] || die "one version only"; VERSION="$1"; shift;;
    esac
done
mkdir -p "$REPO_DIR/build"
case "$MODE" in
    compare) version_gt "${ARGS[0]}" "${ARGS[1]}";;
    changelog) changelog_entry "${ARGS[0]}" "$NOTES";;
    setup) [ -z "$VERSION" ] || die "--setup takes no version"; setup;;
    release) [ -n "$VERSION" ] || die "usage: scripts/release.sh <version> | --setup (see --help)"; release "$VERSION" "$CHECK" "$WAIT" "$YES" "$NOTES";;
esac
