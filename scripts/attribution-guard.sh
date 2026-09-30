#!/usr/bin/env bash
# =============================================================================
# attribution-guard.sh — tools are never credited. Refuses tool names, tool
# trailers, and tool footers in tracked files and commit messages.
#
#   attribution-guard.sh tree            scan every tracked file
#   attribution-guard.sh msg <file>      scan one commit message (commit-msg hook)
#   attribution-guard.sh range <a>..<b>  scan every commit message in a range
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="scripts/attribution-guard.sh"

PATTERN='(^|[^[:alnum:]])(claude|anthropic|openai|chatgpt|copilot|codex|gemini)([^[:alnum:]]|$)|assisted-by:|co-authored-by:|generated (with|by) \[?(an? )?(ai|llm|tool)'

fail() { echo "FAIL: $1"; exit 1; }

case "${1:-}" in
    tree)
        if git -C "$ROOT" ls-files -z | grep -zv "^$SELF\$" \
            | (cd "$ROOT" && xargs -0 grep -nIiE "$PATTERN" --); then
            fail "tool attribution or tool reference in tracked files"
        fi
        # File and directory names count too.
        if git -C "$ROOT" ls-files | grep -v "^$SELF\$" | grep -iE "$PATTERN"; then
            fail "tool reference in a tracked path"
        fi
        ;;
    msg)
        [[ -f "${2:-}" ]] || fail "usage: $0 msg <file>"
        if grep -v '^#' "$2" | grep -niE "$PATTERN"; then
            fail "tool attribution in commit message"
        fi
        ;;
    range)
        [[ -n "${2:-}" ]] || fail "usage: $0 range <a>..<b>"
        if git -C "$ROOT" log --format='%H%n%an <%ae>%n%cn <%ce>%n%B' "$2" | grep -niE "$PATTERN"; then
            fail "tool attribution in commit messages or identities of $2"
        fi
        ;;
    *)
        fail "usage: $0 tree | msg <file> | range <a>..<b>"
        ;;
esac
