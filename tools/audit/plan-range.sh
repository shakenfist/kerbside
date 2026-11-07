#!/bin/bash

# Usage: tools/audit/plan-range.sh <merge-sha> [<merge-sha> ...]
#
# Derives an AUDIT_RANGE and an AUDIT_PATHS from a plan's merge
# commits, for tools/audit/wave1.sh and tools/audit/wave2-mechanical.sh
# to audit an accumulated range whose work has already merged to
# develop (where a plain diff against develop is empty and a
# vacuous pass). For each SHA given, this unions the files touched by
# that merge (git diff --name-only "$sha^1..$sha") into a path set,
# and emits one range per merge, "$sha^1..$sha".
#
# One range per merge rather than a single span from the first merge's
# parent to the last. A plan's work is what its merges landed, and the
# span between them is not that: it also holds every other commit that
# touched a file the plan touched, and the path set cannot exclude
# those, because they are changes to the very paths it scopes to. The
# audit of PLAN-use-case-docs.md credited the plan with 991 added
# Python lines against the 758 its merges landed, 233 of them issue
# #132's secret-redaction tests, which three judgment agents then
# reviewed as the plan's own work. "$sha^1..$sha" is exactly what one
# merge landed, so the union over the merges is exactly the plan's.
#
# Prints exactly two lines to stdout, each an `export` statement, so
# the caller can do:
#
#   eval "$(tools/audit/plan-range.sh 14b54f3 2e1fd43)"
#
# Where both `develop` and `origin/develop` resolve, the newer of the
# two is the base branch: a stale local ref rejects a merge that has
# landed, and says so in terms of the SHA rather than the ref.
#
# Fails loudly (exit 1, message to stderr) if fewer than one SHA is
# given, if neither `develop` nor `origin/develop` resolves, if any
# SHA is not a commit, if any SHA is not an ancestor of the base
# branch, if the SHAs are not given oldest-first, if the derived path
# set is empty, or if any derived path contains whitespace, a glob
# metacharacter or a quoting character -- the audit scripts rely on
# AUDIT_PATHS being word-split into a git argument list, and the
# caller evals it out of a single-quoted string, so such a path would
# silently narrow the audit rather than loudly breaking it.

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
#
# Where both resolve, take the newer -- whichever contains the other.
# The base ref exists only to answer "did this merge land on the
# project's mainline", so a ref that is too new cannot produce a wrong
# answer while a stale one can: a worktree whose main clone has an old
# `develop` checked out cannot fast-forward it from here (another
# worktree holds it), and the ancestry check below then rejects a
# current merge commit while naming the SHA rather than the stale ref.
local_base=""
remote_base=""
git rev-parse --verify 'develop^{commit}' >/dev/null 2>&1 \
    && local_base="develop"
git rev-parse --verify 'origin/develop^{commit}' >/dev/null 2>&1 \
    && remote_base="origin/develop"

base_ref=""
if [ -n "${local_base}" ] && [ -n "${remote_base}" ]; then
    if git merge-base --is-ancestor develop origin/develop 2>/dev/null; then
        # Equal refs take this arm; say nothing in that case, which is
        # the common one, and name the staleness only when there is
        # some.
        base_ref="${remote_base}"
        if ! git merge-base --is-ancestor origin/develop develop \
                2>/dev/null; then
            echo "plan-range.sh: local 'develop' is behind" >&2
            echo "  'origin/develop'; using 'origin/develop'." >&2
        fi
    elif git merge-base --is-ancestor origin/develop develop 2>/dev/null; then
        base_ref="${local_base}"
    else
        # Neither contains the other. origin/develop is the authority
        # on what landed, so a diverged local develop is not evidence
        # of anything; use the remote and say which one was used,
        # rather than failing a run that has a perfectly good base.
        base_ref="${remote_base}"
        echo "plan-range.sh: local 'develop' has diverged from" >&2
        echo "  'origin/develop'; using 'origin/develop'." >&2
    fi
else
    base_ref="${local_base}${remote_base}"
fi

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
    # The path set below diffs "${sha}^1..${sha}", so a commit with no
    # first parent aborts there under set -e with git's own "ambiguous
    # argument" and exit 128, rather than this script's own message
    # naming the problem.
    if ! git rev-parse --verify "${sha}^1^{commit}" >/dev/null 2>&1; then
        echo "plan-range.sh: '${sha}' has no first parent; give the" >&2
        echo "  merge commits a plan's phases landed as." >&2
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

# The SHAs must be given oldest-first. Each range is now "$sha^1..$sha"
# and so diffs forwards whatever order they arrive in, which retires
# the hazard this guard was written for: a reversed single span diffed
# backwards, the phases' additions appeared as deletions, and the '^\+'
# style checks inspected reverted content and passed on work they never
# saw, while the path set still looked entirely correct.
#
# It stays because the ranges are audited and reported in the order
# given, and a reader following a plan's phases through the output
# needs them in landing order. It is also the one check that a list
# assembled from the wrong end of a plan's phase table is wrong.
if ! git merge-base --is-ancestor "${first_sha}" "${last_sha}" 2>/dev/null; then
    echo "plan-range.sh: '${first_sha}' is not an ancestor of" >&2
    echo "  '${last_sha}'; give the merge SHAs oldest-first." >&2
    exit 1
fi

paths=""
for sha in "$@"; do
    # core.quotePath=false so a non-ASCII path comes out literal rather
    # than as "caf\303\251.py", which carries neither whitespace nor a
    # glob character, survives the guard below, and then matches nothing
    # when the wave scripts hand it back to git -- a silently narrowed
    # audit, which is the exact failure the guard exists to stop.
    files=$(git -c core.quotePath=false diff --name-only "${sha}^1..${sha}")
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
        *[[:space:]*?[\'\"\\]*)
            # A single quote would terminate the quoting in the emitted
            # export line and hand the remainder to the caller's shell;
            # git does not escape one on output.
            echo "plan-range.sh: path contains whitespace, a glob" >&2
            echo "  metacharacter or a quoting character: ${path}" >&2
            exit 1
            ;;
    esac
done <<< "${paths}"

audit_paths=$(printf '%s\n' "${paths}" | tr '\n' ' ')
audit_paths="${audit_paths% }"

# One range per merge, in the order given. The path set is emitted as
# well, so a hand-set AUDIT_RANGE still has something to scope it and
# the wave scripts keep one contract; against these ranges it is
# belt-and-braces, since each merge's own diff touches only paths the
# union already holds.
audit_ranges=""
for sha in "$@"; do
    audit_ranges="${audit_ranges}${audit_ranges:+ }${sha}^1..${sha}"
done

echo "export AUDIT_RANGE='${audit_ranges}'"
echo "export AUDIT_PATHS='${audit_paths}'"
