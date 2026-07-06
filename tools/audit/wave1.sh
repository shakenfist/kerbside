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
#
# The fatal style checks (3, 4) inspect only lines ADDED relative to
# develop, so pre-existing intentional prints (config/logging
# bootstrap, the kerbside-util CLI) do not trip them. A print() may
# still be added deliberately if its file carries the marker comment
# `audit-allow-print`.
#
# Usage: tools/audit/wave1.sh   (run from the worktree root)

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

DIFF_BASE=develop

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

bold "=== wave 1b: mechanical style checks ==="

have_base=0
if git rev-parse --verify "$DIFF_BASE" >/dev/null 2>&1; then
    have_base=1
else
    echo "ADVISORY: cannot find '$DIFF_BASE'; skipping diff-based style checks"
fi

if [[ "$have_base" == "1" ]]; then
    # Added .py lines in the diff, excluding tests and generated stubs.
    ADDED=$(git diff "$DIFF_BASE"...HEAD -- '*.py' ':!*/tests/*' ':!*_pb2*' ':!*_pb2_grpc*' \
        | grep -E '^\+' | grep -v '^\+\+\+' || true)

    # 1. No raw print() added (logging only). Skip if the changed file
    #    carries the `audit-allow-print` marker.
    PRINT_HITS=$(printf '%s\n' "$ADDED" | grep -E '^\+[[:space:]]*print\(' || true)
    if [[ -n "$PRINT_HITS" ]]; then
        # Only fatal if no changed file opted in via the marker.
        MARKED=$(git diff "$DIFF_BASE"...HEAD --name-only -- '*.py' \
            | xargs -r grep -l 'audit-allow-print' 2>/dev/null || true)
        if [[ -z "$MARKED" ]]; then
            red "FAIL: raw print() added in non-test source:"
            echo "$PRINT_HITS"
            exit 3
        fi
    fi
    green "PASS: no raw print() added"

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
    LONG=$(git diff "$DIFF_BASE"...HEAD --name-only -- '*.py' ':!*_pb2*' \
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
