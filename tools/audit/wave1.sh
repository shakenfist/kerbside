#!/usr/bin/env bash
# wave1.sh — pre-push audit, mechanical wave (kerbside).
#
# Adapted from shakenfist/ryll/tools/audit/wave1.sh: the lint/test
# gates are tox (flake8 + py3) instead of cargo/docker, and the
# style greps are Python-flavoured.
#
# Exit code:
#   0  all checks passed
#   1  flake8 failed
#   2  py3 test suite failed
#   3  raw print() added in non-test source (logging only)
#   4  bare `except:` added in source
#   6  an explicitly-set AUDIT_RANGE does not resolve
#
# The fatal style checks (3, 4) inspect only lines ADDED relative to
# AUDIT_RANGE (develop...HEAD by default), so pre-existing intentional
# prints (config/logging bootstrap, the kerbside CLI) do not trip
# them. A print() may still be added deliberately if its file carries
# the marker comment `audit-allow-print`.
#
# Usage: tools/audit/wave1.sh   (run from the worktree root)
#
# AUDIT_SKIP_TOX=1 skips the wave 1a tox gates and runs only the
# wave 1b mechanical checks.
#
# AUDIT_RANGE and AUDIT_PATHS may be set in the environment to audit
# an accumulated range instead of a live branch -- a branch whose
# work has already merged to develop otherwise diffs empty and passes
# vacuously. tools/audit/plan-range.sh derives both from a plan's
# merge commits. Defaults, unset: AUDIT_RANGE=develop...HEAD,
# AUDIT_PATHS='' (no path restriction) -- today's behaviour exactly.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 5

# The system tox rejects non-boolean FORCE_COLOR values (e.g. "3");
# normalise it so the tox invocations below are robust.
export FORCE_COLOR=1

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

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

# Git unions positive pathspecs rather than intersecting them, so a
# caller's '*.py' cannot simply be appended to $AUDIT_PATHS -- that
# would mean "anything in AUDIT_PATHS, OR any .py anywhere in the
# range", re-admitting the unrelated merges AUDIT_PATHS exists to
# exclude. Intersect in two stages instead: scope by AUDIT_PATHS plus
# the caller's exclusions, then filter the resulting file list by
# name.
#
# audit_paths_for <filename-ere> [exclusion pathspec...]
audit_paths_for() {
    local pattern="$1"
    shift
    # shellcheck disable=SC2086  # word splitting builds the arg list
    git diff --name-only $AUDIT_RANGE -- $AUDIT_PATHS "$@" \
        | grep -E "$pattern" || true
}

# audit_diff_for <filename-ere> [exclusion pathspec...]
audit_diff_for() {
    local pattern="$1"
    shift
    local files
    files=$(audit_paths_for "$pattern" "$@")
    [ -n "$files" ] || return 0
    # shellcheck disable=SC2086  # word splitting builds the arg list
    git diff $AUDIT_RANGE -- $files
}

# AUDIT_SKIP_TOX=1 runs wave 1b alone. The two fatal style checks
# below had never inspected a line for six weeks because nothing
# exercised them; they are only cheaply testable if they can be
# reached without a full tox cycle first. It is also the fast path
# for re-running the mechanical checks while fixing one of them.
if [[ "${AUDIT_SKIP_TOX:-0}" != "1" ]]; then
    bold "=== wave 1a: flake8 (tox -eflake8) ==="
    if ! tox -eflake8; then
        red "FAIL: flake8"
        exit 1
    fi
    green "PASS: flake8"
    echo

    bold "=== wave 1a: unit tests (tox -epy3) ==="
    if ! tox -epy3; then
        red "FAIL: py3 tests"
        exit 2
    fi
    green "PASS: py3 tests"
    echo
fi

bold "=== wave 1b: mechanical style checks ==="

# Validate both ends of the range, not just the base. A range whose tip
# does not resolve makes every git diff below emit "fatal: bad
# revision" to stderr and produce nothing, so every check reports clean
# and the script exits 0 having inspected nothing.
#
# Split the base at '..' rather than at the first '.': a dotted ref
# ("v0.5.0..HEAD") truncates to "v0" under '%%.*', which does not
# resolve, and the guard then skips everything for the same reason.
# '%%..*' leaves a dotless single ref untouched.
#
# An explicitly-set AUDIT_RANGE that does not resolve is fatal: the
# operator asked for a specific range and would otherwise get a green
# report over nothing. The default range keeps the original tolerance.
have_base=0
if git rev-parse --verify "${AUDIT_RANGE%%..*}" >/dev/null 2>&1 \
        && git rev-parse --verify "${AUDIT_RANGE##*..}" >/dev/null 2>&1; then
    have_base=1
elif [[ "$AUDIT_RANGE_EXPLICIT" == "1" ]]; then
    red "FAIL: AUDIT_RANGE '$AUDIT_RANGE' does not resolve"
    exit 6
else
    echo "ADVISORY: cannot resolve '$AUDIT_RANGE'; skipping diff-based style checks"
fi

if [[ "$have_base" == "1" ]]; then
    # Added .py lines in the diff, excluding tests and generated stubs.
    # The second grep needs -E: in BRE (the default), \+ is the
    # repetition operator, so an unescaped '^\+\+\+' matches any run
    # of leading '+' and strips every added line, not just the
    # '+++ b/<path>' diff headers. -E makes \+ a literal '+'.
    ADDED=$(audit_diff_for '\.py$' ':!*/tests/*' ':!*_pb2*' ':!*_pb2_grpc*' \
        | grep -E '^\+' | grep -vE '^\+\+\+' || true)

    # 1. No raw print() added (logging only). Skip if the changed file
    #    carries the `audit-allow-print` marker.
    PRINT_HITS=$(printf '%s\n' "$ADDED" | grep -E '^\+[[:space:]]*print\(' || true)
    if [[ -n "$PRINT_HITS" ]]; then
        # Only fatal if no changed file opted in via the marker.
        MARKED=$(audit_paths_for '\.py$' \
            | xargs -r grep -l 'audit-allow-print' 2>/dev/null || true)
        if [[ -z "$MARKED" ]]; then
            red "FAIL: raw print() added in non-test source:"
            echo "$PRINT_HITS"
            exit 3
        fi
        # The marker suppresses the check for the whole diff, not just
        # the file carrying it, so name the file that granted the
        # exemption: otherwise a branch that happens to touch a marked
        # file gets no print check at all and the output looks like a
        # clean pass. Narrowing the suppression to the marked file is
        # a fleet-wide change to the audit scripts and is deliberately
        # left upstream; making it visible is not.
        green "PASS (suppressed): print() added, exempted by the marker in:"
        echo "$MARKED"
    else
        green "PASS: no raw print() added"
    fi

    # 2. No bare `except:` added.
    BARE_EXCEPT=$(printf '%s\n' "$ADDED" | grep -E '^\+[[:space:]]*except[[:space:]]*:' || true)
    if [[ -n "$BARE_EXCEPT" ]]; then
        red "FAIL: bare 'except:' added:"
        echo "$BARE_EXCEPT"
        exit 4
    fi
    green "PASS: no bare except added"

    # 3. Advisory: `except Exception` added without an obvious re-raise
    #    or logged message nearby (heuristic; verify in wave 2a).
    BROAD=$(printf '%s\n' "$ADDED" | grep -E '^\+[[:space:]]*except Exception' || true)
    if [[ -n "$BROAD" ]]; then
        echo "ADVISORY: 'except Exception' added (confirm each re-raises or logs):"
        echo "$BROAD"
    fi

    # 4. Advisory: long lines (>120) added to changed .py files.
    LONG=$(audit_paths_for '\.py$' ':!*_pb2*' \
        | xargs -r awk 'length > 120 {print FILENAME":"NR": "length" chars"}' 2>/dev/null || true)
    if [[ -n "$LONG" ]]; then
        echo "ADVISORY: lines over 120 chars in changed .py files:"
        echo "$LONG" | head -20
    fi

    # 5. Advisory: trailing whitespace added.
    WS=$(printf '%s\n' "$ADDED" | grep -nE '[[:space:]]+$' || true)
    if [[ -n "$WS" ]]; then
        echo "ADVISORY: trailing whitespace on added lines"
    fi
fi

green "PASS: wave 1b mechanical"
echo

bold "=== wave 1 complete ==="
green "all mechanical checks passed; proceed to wave 2 (judgment agents)"
exit 0
