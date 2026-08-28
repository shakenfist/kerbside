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
# given, if any SHA is not a commit, if any SHA is not an ancestor of
# develop, or if any derived path contains whitespace -- the audit
# scripts rely on AUDIT_PATHS being word-split into a git argument
# list, so a whitespace-containing path would silently narrow the
# audit rather than loudly breaking it.

set -e

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <merge-sha> [<merge-sha> ...]" >&2
    exit 1
fi

for sha in "$@"; do
    if ! git rev-parse --verify "${sha}^{commit}" >/dev/null 2>&1; then
        echo "plan-range.sh: '${sha}' is not a commit" >&2
        exit 1
    fi
    if ! git merge-base --is-ancestor "${sha}" develop; then
        echo "plan-range.sh: '${sha}' is not an ancestor of develop" >&2
        exit 1
    fi
done

first_sha="$1"
# shellcheck disable=SC2124
last_sha="${@: -1}"

paths=""
for sha in "$@"; do
    files=$(git diff --name-only "${sha}^1..${sha}")
    paths="${paths}
${files}"
done

paths=$(printf '%s\n' "${paths}" | sort -u | grep -v '^$' || true)

while IFS= read -r path; do
    case "${path}" in
        *[[:space:]]*)
            echo "plan-range.sh: path contains whitespace: '${path}'" >&2
            exit 1
            ;;
    esac
done <<< "${paths}"

audit_paths=$(printf '%s\n' "${paths}" | tr '\n' ' ')
audit_paths="${audit_paths% }"

echo "export AUDIT_RANGE='${first_sha}^1..${last_sha}'"
echo "export AUDIT_PATHS='${audit_paths}'"
