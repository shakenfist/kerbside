#!/bin/bash

# Usage: tools/audit/plan-range.sh <merge-sha> [<merge-sha> ...]
#
# Derives an AUDIT_RANGE and an AUDIT_PATHS from a plan's merge
# commits, for tools/audit/wave1.sh and tools/audit/wave2-mechanical.sh
# to audit an accumulated range whose work has already merged to
# develop (where a plain diff against develop is empty and a
# vacuous pass). For each SHA given, this unions the files touched by
# that merge (git diff --name-only "$sha^1..$sha") into a path set,
# and spans the range from the first SHA's parent to the last SHA.
#
# Prints exactly two lines to stdout, each an `export` statement, so
# the caller can do:
#
#   eval "$(tools/audit/plan-range.sh 14b54f3 2e1fd43)"
#
# Fails loudly (exit 1, message to stderr) if fewer than one SHA is
# given, if neither `develop` nor `origin/develop` resolves, if any
# SHA is not a commit, if any SHA is not an ancestor of the base
# branch, if the SHAs are not given oldest-first, if the derived path
# set is empty, or if any derived path contains whitespace or a glob
# metacharacter -- the audit scripts rely on AUDIT_PATHS being
# word-split into a git argument list, so such a path would silently
# narrow the audit rather than loudly breaking it.

set -e

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <merge-sha> [<merge-sha> ...]" >&2
    exit 1
fi

# A CI-style PR checkout has only origin/develop, no local develop, so
# resolve the base branch rather than hard-coding the bare ref: an
# unresolvable ref used to surface as git's own "Not a valid object
# name develop" followed by this script blaming ancestry, which sends
# the reader after the wrong problem entirely.
base_ref=""
for candidate in develop origin/develop; do
    if git rev-parse --verify "${candidate}^{commit}" >/dev/null 2>&1; then
        base_ref="${candidate}"
        break
    fi
done

if [ -z "${base_ref}" ]; then
    echo "plan-range.sh: cannot resolve 'develop' or 'origin/develop';" >&2
    echo "  fetch the base branch before deriving an audit range." >&2
    exit 1
fi

for sha in "$@"; do
    if ! git rev-parse --verify "${sha}^{commit}" >/dev/null 2>&1; then
        echo "plan-range.sh: '${sha}' is not a commit" >&2
        exit 1
    fi
    if ! git merge-base --is-ancestor "${sha}" "${base_ref}" 2>/dev/null; then
        echo "plan-range.sh: '${sha}' is not an ancestor of ${base_ref}" >&2
        exit 1
    fi
done

first_sha="$1"
# shellcheck disable=SC2124
last_sha="${@: -1}"

# The SHAs must be given oldest-first. Reversed, the derived range
# diffs backwards -- the phases' additions appear as deletions, so the
# '^\+' style checks inspect reverted content and pass on work they
# never saw -- while the path set still looks entirely correct, which
# is what makes the mistake hard to spot in the output.
if ! git merge-base --is-ancestor "${first_sha}" "${last_sha}" 2>/dev/null; then
    echo "plan-range.sh: '${first_sha}' is not an ancestor of" >&2
    echo "  '${last_sha}'; give the merge SHAs oldest-first." >&2
    exit 1
fi

paths=""
for sha in "$@"; do
    files=$(git diff --name-only "${sha}^1..${sha}")
    paths="${paths}
${files}"
done

paths=$(printf '%s\n' "${paths}" | sort -u | grep -v '^$' || true)

# An empty path set can only mean the SHAs were wrong, and both audit
# scripts read an empty AUDIT_PATHS as "no path restriction" -- so
# emitting one silently widens the audit to the whole range, the same
# class of quiet-wrong-answer as the narrowing the guard below stops.
if [ -z "${paths}" ]; then
    echo "plan-range.sh: derived path set is empty; the SHAs given" >&2
    echo "  touch no files." >&2
    exit 1
fi

while IFS= read -r path; do
    case "${path}" in
        *[[:space:]*?[]*)
            echo "plan-range.sh: path contains whitespace or a glob" >&2
            echo "  metacharacter: '${path}'" >&2
            exit 1
            ;;
    esac
done <<< "${paths}"

audit_paths=$(printf '%s\n' "${paths}" | tr '\n' ' ')
audit_paths="${audit_paths% }"

echo "export AUDIT_RANGE='${first_sha}^1..${last_sha}'"
echo "export AUDIT_PATHS='${audit_paths}'"
