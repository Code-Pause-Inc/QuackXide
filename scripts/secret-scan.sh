#!/usr/bin/env bash
# =============================================================================
# secret-scan.sh — gitleaks over every diff in HEAD's history, under
# .gitleaks.toml. CI runs it on a pull request's merge with main, and
# scripts/check.sh on the checked-out branch. Fails closed: a scan that git
# cut short, which gitleaks alone reports as clean, is a failure.
#
#   secret-scan.sh            scan HEAD's history
#   secret-scan.sh selftest   check the scan catches known cases
#
# GITLEAKS names the gitleaks binary (default: gitleaks on PATH).
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GITLEAKS="${GITLEAKS:-gitleaks}"
# Attributes come from the empty tree, so a committed .gitattributes can't
# mark files -diff or binary and drop them from the scan.
EMPTY_TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904

fail() { echo "FAIL: $1"; exit 1; }

# GIT_ATTR_SOURCE needs git 2.41 or later; older git silently ignores it.
v="$(git version)"
IFS=. read -r major minor _ <<<"${v#git version }"
(( major > 2 || (major == 2 && minor >= 41) )) \
    || fail "git 2.41 or later is needed (GIT_ATTR_SOURCE); this is $v"

# scan <repo>: only HEAD's history, so other branches' allowlists never
# apply. Merges are diffed against their first parent, so a conflict
# resolution is scanned too.
scan() {
    local rev out status=0
    rev="$(git -C "$1" rev-parse --verify --quiet 'HEAD^{commit}')" \
        || { echo "FAIL: no commit at HEAD in $1"; return 1; }
    out="$(GIT_ATTR_SOURCE="$EMPTY_TREE" "$GITLEAKS" git --no-banner --no-color --redact -v \
        --config "$ROOT/.gitleaks.toml" \
        --log-opts="--no-color --diff-merges=first-parent $rev --" "$1" 2>&1)" || status=$?
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
    return "$status"
}

case "${1:-}" in
    "")
        scan "$ROOT"
        ;;
    selftest)
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
