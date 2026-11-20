#!/usr/bin/env bash
# =============================================================================
# check-codeowners.sh — every pattern in .github/CODEOWNERS matches at least
# one tracked path. GitHub does not flag a pattern that matches nothing, so a
# typo would silently drop code-owner review for the path it meant.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mapfile -t tracked < <(git -C "$ROOT" ls-files)
status=0
while read -r pattern _; do
    pattern="${pattern%$'\r'}"
    case "${pattern}" in '' | '#'*) continue ;; esac
    if [[ "${pattern}" != /* ]]; then
        echo "FAIL: ${pattern}: anchor CODEOWNERS patterns at the repository root"
        status=1
        continue
    fi
    glob="${pattern#/}"
    # A directory pattern owns everything below it.
    [[ "${glob}" == */ ]] && glob="${glob}*"
    matched=0
    for path in "${tracked[@]}"; do
        # shellcheck disable=SC2053 # the pattern is a glob on purpose
        if [[ "${path}" == ${glob} ]]; then
            matched=1
            break
        fi
    done
    if [[ "${matched}" -eq 0 ]]; then
        echo "FAIL: ${pattern} matches no tracked path"
        status=1
    fi
done < "$ROOT/.github/CODEOWNERS"
exit "${status}"
