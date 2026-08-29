#!/usr/bin/env bash
# wave2-mechanical.sh — pre-push audit, scriptable parts of wave 2 (kerbside).
#
# Adapted from shakenfist/ryll/tools/audit/wave2-mechanical.sh for a
# Python codebase. Reports findings as plain text; never exits
# non-zero on findings. Read the output and decide what to fix, then
# spawn the judgment agents (2a code-quality, 2b tests, 2c docs,
# 2d security).
#
# Usage: tools/audit/wave2-mechanical.sh   (run from the worktree root)
#
# AUDIT_RANGE and AUDIT_PATHS may be set in the environment to audit
# an accumulated range instead of a live branch -- a branch whose
# work has already merged to develop otherwise diffs empty and every
# report below prints "(none)". tools/audit/plan-range.sh derives
# both from a plan's merge commits. Defaults, unset:
# AUDIT_RANGE=develop...HEAD, AUDIT_PATHS='' (no path restriction) --
# today's behaviour exactly.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

# Default to develop...HEAD, but resolve origin/develop when there is
# no local develop: a fetched PR checkout has only the remote ref, and
# the bare default there resolves to nothing, skips every diff-based
# check and still reports success. Where develop exists this is
# today's default unchanged.
AUDIT_RANGE_EXPLICIT=1
if [ -z "${AUDIT_RANGE:-}" ]; then
    AUDIT_RANGE_EXPLICIT=0
    if git rev-parse --verify develop >/dev/null 2>&1; then
        AUDIT_RANGE="develop...HEAD"
    elif git rev-parse --verify origin/develop >/dev/null 2>&1; then
        AUDIT_RANGE="origin/develop...HEAD"
    else
        AUDIT_RANGE="develop...HEAD"
    fi
fi
AUDIT_PATHS="${AUDIT_PATHS:-}"
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

# Git unions positive pathspecs rather than intersecting them, so a
# caller's '*.py' cannot simply be appended to $AUDIT_PATHS -- that
# would mean "anything in AUDIT_PATHS, OR any .py anywhere in the
# range", re-admitting the unrelated merges AUDIT_PATHS exists to
# exclude. Intersect in two stages instead: scope by AUDIT_PATHS plus
# the caller's exclusions, then filter the resulting file list by
# name.
#
# Both helpers round-trip a filename back into a pathspec, so both
# hazards of that round trip are closed here rather than relied on
# from plan-range.sh -- the file list below is derived from the range,
# not from AUDIT_PATHS, so plan-range.sh's guards never see it:
#
#   * core.quotePath=false, or git renders a non-ASCII path as
#     "caf\303\251.py", which then matches nothing when handed back
#     and silently drops the file from the audit.
#   * an array rather than an unquoted string, so a filename
#     containing whitespace or a glob character is neither split nor
#     expanded against the working tree.
#
# audit_paths_for <filename-ere> [exclusion pathspec...]
audit_paths_for() {
    local pattern="$1"
    shift
    local -a scope=()
    if [ -n "$AUDIT_PATHS" ]; then
        # AUDIT_PATHS is a space-separated list, so it is deliberately
        # word-split -- but with globbing off, which set -f does
        # without disabling the splitting.
        set -f
        # shellcheck disable=SC2206  # deliberate split, globbing off
        scope=($AUDIT_PATHS)
        set +f
    fi
    git -c core.quotePath=false diff --name-only "$AUDIT_RANGE" \
            -- "${scope[@]}" "$@" \
        | grep -E "$pattern" || true
}

# audit_diff_for <filename-ere> [exclusion pathspec...]
audit_diff_for() {
    local pattern="$1"
    shift
    local -a files=()
    mapfile -t files < <(audit_paths_for "$pattern" "$@")
    [ "${#files[@]}" -gt 0 ] || return 0
    git -c core.quotePath=false diff "$AUDIT_RANGE" -- "${files[@]}"
}

# See wave1.sh for why both ends are validated and why the base is
# split at '..' rather than at the first '.'.
if ! git rev-parse --verify "${AUDIT_RANGE%%..*}" >/dev/null 2>&1 \
        || ! git rev-parse --verify "${AUDIT_RANGE##*..}" >/dev/null 2>&1; then
    if [ "$AUDIT_RANGE_EXPLICIT" = "1" ]; then
        echo "FAIL: AUDIT_RANGE '$AUDIT_RANGE' does not resolve" >&2
        exit 1
    fi
    echo "cannot resolve '$AUDIT_RANGE'; nothing to diff"
    exit 0
fi

bold "=== wave 2a: TODO / FIXME / HACK / XXX in changed files ==="
# These two still work through the trailing grep's own exit status,
# but capture and branch like every other section: relying on what
# happens to be last in the pipeline is how the three sections above
# lost their fallback in the first place.
HITS=$(audit_paths_for '\.py$' \
    | xargs -r grep -nH -E '\b(TODO|FIXME|HACK|XXX)\b' 2>/dev/null \
    | grep -v 'docs/plans/' || true)
[[ -n "$HITS" ]] && echo "$HITS" || echo "(none)"
echo

bold "=== wave 2a: new # noqa annotations in changed files ==="
HITS=$(audit_diff_for '\.py$' | grep -E '^\+.*# noqa' || true)
[[ -n "$HITS" ]] && echo "$HITS" || echo "(none)"
echo

bold "=== wave 2b: new test count vs python files changed ==="
NEW_TESTS=$(audit_diff_for '\.py$' \
    | grep -cE '^\+[[:space:]]*def test_' || true)
echo "new test_ functions: $NEW_TESTS"
NEW_PY=$(audit_paths_for '\.py$' | grep -vc '_pb2' || true)
echo "python files changed (excl. generated pb2): $NEW_PY"
echo

bold "=== wave 2c: doc files touched in changed set ==="
DOCS=$(audit_paths_for '^(README\.md|ARCHITECTURE\.md|AGENTS\.md|docs/)' || true)
if [[ -n "$DOCS" ]]; then
    echo "$DOCS"
else
    echo "WARNING: no documentation files touched. Did the changes merit doc updates?"
fi
echo

bold "=== wave 2d: security smoke ==="
echo "new broad 'except Exception' blocks (review: re-raise or logged?):"
# Capture rather than piping straight to head: a pipeline's status is
# the last command's, so `... | head -20 || echo "(none)"` never fires
# the fallback and an empty section is indistinguishable from one that
# failed to run.
HITS=$(audit_diff_for '\.py$' \
    | grep -nE '^\+[[:space:]]*except Exception' | head -20 || true)
[[ -n "$HITS" ]] && echo "$HITS" || echo "(none)"
echo

echo "new assert statements in non-test code (stripped under python -O):"
HITS=$(audit_diff_for '\.py$' ':!*/tests/*' \
    | grep -nE '^\+[[:space:]]*assert ' | head -20 || true)
[[ -n "$HITS" ]] && echo "$HITS" || echo "(none)"
echo

echo "dependency changes (pyproject.toml / bindep.txt) — surface for security review:"
HITS=$(audit_diff_for '^(pyproject\.toml|bindep\.txt)$' \
    | grep -E '^[+-]' | grep -viE '^[+-]{3} ' | head -40 || true)
[[ -n "$HITS" ]] && echo "$HITS" || echo "(none)"
echo

echo "new alembic revisions — surface for migration review:"
# audit_paths_for ends in `|| true`, so it always exits 0 and a bare
# `|| echo "(none)"` after it is dead code. Capture and branch, as
# every other section that cannot rely on a trailing grep does.
HITS=$(audit_paths_for '^kerbside/migrations/versions/.*\.py$')
[[ -n "$HITS" ]] && echo "$HITS" || echo "(none)"
echo

bold "=== wave 2 mechanical complete ==="
echo "now spawn agents for the judgment-needing parts:"
echo "  2a: code quality / missed abstractions / DB lifecycle"
echo "  2b: test coverage"
echo "  2c: doc accuracy vs code intent"
echo "  2d: security review (input validation, auth, tickets, TLS, SQL, audit)"
exit 0
