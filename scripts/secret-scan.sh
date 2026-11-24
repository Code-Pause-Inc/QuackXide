#!/usr/bin/env bash
# =============================================================================
# secret-scan.sh — gitleaks over every diff and every commit message in
# HEAD's history, under .gitleaks.toml. CI runs it on a pull request's merge
# with main and on every push to every branch, and scripts/check.sh on the
# checked-out branch. Fails closed: a scan that git cut short, which gitleaks
# alone reports as clean, is a failure.
#
#   secret-scan.sh            scan HEAD's history
#   secret-scan.sh selftest   check the scan catches known cases
#
# GITLEAKS names the gitleaks binary (default: gitleaks on PATH).
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GITLEAKS="${GITLEAKS:-gitleaks}"

fail() { echo "FAIL: $1"; exit 1; }

# scan <repo>: only HEAD's history, so other branches' allowlists never
# apply. Merges are diffed against their first parent, so a conflict
# resolution is scanned too. --text --no-textconv diff every file's real
# content, so attributes (-diff, binary, a textconv driver, in the repo or
# the user's config) and NUL bytes can't hide a secret. The diffs never
# include commit messages, which a squash merge copies onto main, so those
# go through `gitleaks stdin` too.
scan() {
    local rev out messages status=0 message_status=0
    rev="$(git -C "$1" rev-parse --verify --quiet 'HEAD^{commit}')" \
        || { echo "FAIL: no commit at HEAD in $1"; return 1; }
    out="$("$GITLEAKS" git --no-banner --no-color --redact -v \
        --config "$ROOT/.gitleaks.toml" \
        --log-opts="--no-color --text --no-textconv --diff-merges=first-parent $rev --" "$1" 2>&1)" || status=$?
    printf '%s\n' "$out"
    # gitleaks logs a git error, stops reading, and still exits 0; output it
    # cannot parse scans no commits.
    if grep -qE '^[^ ]+ ERR ' <<<"$out"; then
        echo "FAIL: git stopped partway, so the scan is incomplete"
        return 1
    fi
    if grep -qE '^[^ ]+ INF 0 commits scanned' <<<"$out"; then
        echo "FAIL: no commits were scanned, so the scan is incomplete"
        return 1
    fi

    messages="$(git -C "$1" log --no-color --format='commit %H%n%B' "$rev" --)" \
        || { echo "FAIL: git could not list the commit messages, so the scan is incomplete"; return 1; }
    out="$(printf '%s\n' "$messages" | "$GITLEAKS" stdin --no-banner --no-color --redact -v \
        --config "$ROOT/.gitleaks.toml" 2>&1)" || message_status=$?
    printf '%s\n' "$out"
    if grep -qE '^[^ ]+ ERR ' <<<"$out"; then
        echo "FAIL: the commit-message scan stopped partway, so the scan is incomplete"
        return 1
    fi
    if (( status != 0 )); then return "$status"; fi
    return "$message_status"
}

case "${1:-}" in
    "")
        scan "$ROOT"
        ;;
    selftest)
        # A GIT_DIR from a hook or `git rebase -x` would make `git init` below
        # reinitialise, and each case commit into, the caller's repository.
        while read -r var; do unset "$var"; done < <(git rev-parse --local-env-vars)
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        # Scratch repositories, untouched by the user's git config.
        export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
        export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com
        export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
        # Built at run time so this file itself never trips the scan.
        leak="AKIA"
        leak+="Z3MSJV4WQ7XNTEST"

        repo() { git init -q -b main "$tmp/$1" && cd "$tmp/$1"; }
        commit() { git add -A && git commit -qm "$1"; }
        # expect <clean|leak|incomplete> <case>: how the scan must end, so
        # one guard can't pass a case that another should have caught.
        expect() {
            local got=clean
            if ! scan "$tmp/$2" >"$tmp/out" 2>&1; then
                if grep -q '^FAIL: ' "$tmp/out"; then got=incomplete
                elif grep -q 'leaks found: ' "$tmp/out"; then got=leak
                else got=error; fi
            fi
            [[ "$got" == "$1" ]] || { cat "$tmp/out"; fail "selftest: '$2' gave $got, not $1"; }
            echo "ok: $2 ($1)"
        }

        (repo clean && echo ok >a.txt && commit a)
        expect clean clean

        (repo tip && echo "aws_key = \"$leak\"" >a.txt && commit a)
        expect leak tip

        # The key is only in a commit message, which a squash merge copies
        # onto main.
        (repo message && echo ok >a.txt && commit "aws_key = \"$leak\"" \
            && echo b >b.txt && commit b)
        expect leak message

        # A top-level file named HEAD makes a bare HEAD revision ambiguous.
        (repo head-path && echo "aws_key = \"$leak\"" >a.txt && echo x >HEAD && commit a)
        expect leak head-path

        # The key exists only in a merge's conflict resolution.
        (repo merge && echo base >f.txt && commit base \
            && git switch -qc topic && echo topic >f.txt && commit topic \
            && git switch -q main && echo main >f.txt && commit main \
            && { git merge -q topic >/dev/null 2>&1 || true; } \
            && echo "aws_key = \"$leak\"" >f.txt && commit merge)
        expect leak merge

        (repo attributes && echo ok >a.txt && commit a \
            && mkdir fixtures && echo "aws_key = \"$leak\"" >fixtures/k.txt \
            && echo '* -diff' >fixtures/.gitattributes && commit b)
        expect leak attributes

        # A NUL byte makes git treat the file as binary and print no diff.
        (repo nul && echo ok >a.txt && commit a \
            && printf 'aws_key = "%s"\0' "$leak" >k.dat && commit b)
        expect leak nul

        # .git/info/attributes is not committed, so only the scan can undo it.
        (repo info-attributes && echo ok >a.txt && commit a \
            && echo "aws_key = \"$leak\"" >k.txt && commit b \
            && echo 'k.txt -diff' >.git/info/attributes)
        expect leak info-attributes

        (repo color && git config color.ui always && echo "aws_key = \"$leak\"" >a.txt && commit a)
        expect leak color

        # A damaged commit stops git after the newest one, before the key.
        (repo partial && echo "aws_key = \"$leak\"" >a.txt && commit a \
            && echo b >b.txt && commit b && echo c >c.txt && commit c \
            && blob="$(git rev-parse HEAD~1:b.txt)" && rm -f ".git/objects/${blob:0:2}/${blob:2}")
        expect incomplete partial
        ;;
    *)
        fail "usage: $0 [selftest]"
        ;;
esac
