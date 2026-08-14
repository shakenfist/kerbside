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

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

DIFF_BASE=develop
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

if ! git rev-parse --verify "$DIFF_BASE" >/dev/null 2>&1; then
    echo "cannot find '$DIFF_BASE'; nothing to diff"
    exit 0
fi

bold "=== wave 2a: TODO / FIXME / HACK / XXX in changed files ==="
git diff "$DIFF_BASE"...HEAD --name-only \
    | grep -E '\.py$' \
    | xargs -r grep -nH -E '\b(TODO|FIXME|HACK|XXX)\b' 2>/dev/null \
    | grep -v 'docs/plans/' \
    || echo "(none)"
echo

bold "=== wave 2a: new # noqa annotations in changed files ==="
git diff "$DIFF_BASE"...HEAD -- '*.py' \
    | grep -E '^\+.*# noqa' \
    || echo "(none)"
echo

bold "=== wave 2b: new test count vs python files changed ==="
NEW_TESTS=$(git diff "$DIFF_BASE"...HEAD -- '*.py' \
    | grep -cE '^\+[[:space:]]*def test_' || true)
echo "new test_ functions: $NEW_TESTS"
NEW_PY=$(git diff "$DIFF_BASE"...HEAD --name-only -- '*.py' | grep -vc '_pb2' || true)
echo "python files changed (excl. generated pb2): $NEW_PY"
echo

bold "=== wave 2c: doc files touched in changed set ==="
DOCS=$(git diff "$DIFF_BASE"...HEAD --name-only \
    | grep -E '^(README\.md|ARCHITECTURE\.md|AGENTS\.md|docs/)' || true)
if [[ -n "$DOCS" ]]; then
    echo "$DOCS"
else
    echo "WARNING: no documentation files touched. Did the changes merit doc updates?"
fi
echo

bold "=== wave 2d: security smoke ==="
echo "new broad 'except Exception' blocks (review: re-raise or logged?):"
git diff "$DIFF_BASE"...HEAD -- '*.py' \
    | grep -nE '^\+[[:space:]]*except Exception' | head -20 \
    || echo "(none)"
echo

echo "new assert statements in non-test code (stripped under python -O):"
git diff "$DIFF_BASE"...HEAD -- '*.py' ':!*/tests/*' \
    | grep -nE '^\+[[:space:]]*assert ' | head -20 \
    || echo "(none)"
echo

echo "dependency changes (pyproject.toml / bindep.txt) — surface for security review:"
git diff "$DIFF_BASE"...HEAD -- pyproject.toml bindep.txt \
    | grep -E '^[+-]' | grep -viE '^[+-]{3} ' | head -40 \
    || echo "(none)"
echo

echo "new alembic revisions — surface for migration review:"
git diff "$DIFF_BASE"...HEAD --name-only -- 'kerbside/migrations/versions/*.py' \
    || echo "(none)"
echo

bold "=== wave 2 mechanical complete ==="
echo "now spawn agents for the judgment-needing parts:"
echo "  2a: code quality / missed abstractions / DB lifecycle"
echo "  2b: test coverage"
echo "  2c: doc accuracy vs code intent"
echo "  2d: security review (input validation, auth, tickets, TLS, SQL, audit)"
exit 0
