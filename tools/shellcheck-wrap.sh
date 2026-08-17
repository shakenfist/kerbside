#!/bin/bash
# Run shellcheck over every shell script in tools/ and demo/.
#
# This exists so shellcheck runs in CI. The pre-commit hook has covered
# tools/ and demo/ since phase 3 of PLAN-demo-install, but pre-commit is
# not invoked by any workflow or tox environment -- the only mentions in
# .github/workflows are comments in pr-address-comments.yml explaining
# why it is deliberately skipped there -- so until now the shell was
# checked only on machines where a developer had installed the hooks.
#
# The scope deliberately matches .pre-commit-config.yaml's shellcheck
# hook exactly: files under tools/ or demo/, shell only, with -x so
# sourced files are followed. If you change one, change the other, or
# `pre-commit run` and `tox -e shellcheck` will disagree about what
# passes, which is worse than either alone.
#
# File selection is by extension OR shebang, not extension alone: the
# hook uses pre-commit's identify library, which classifies
# demo/kerbside-demo-env and tools/run-tempest-tests as shell despite
# having no .sh suffix. Matching on *.sh only would silently skip them.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# --others --exclude-standard so a new script that is not `git add`ed yet
# is still checked. pre-commit sees staged files, so this cannot disagree
# with the hook about a file being committed -- it only makes the tox
# environment stricter for work in progress, which is the direction a
# developer wants. Writing a new script and having it silently not
# linted is otherwise a standing trap; see the empty-list guard below
# for the last time this class of bug got through.
mapfile -t FILES < <(
    git ls-files --cached --others --exclude-standard tools demo \
            | while read -r f; do
        [ -f "${f}" ] || continue
        case "${f}" in
            *.sh)
                echo "${f}"
                ;;
            *)
                # A shell shebang, however it is spelled: #!/bin/bash,
                # #!/bin/sh, #!/usr/bin/env bash.
                if head -1 "${f}" 2> /dev/null \
                        | grep -qE '^#!.*(\bsh|\bbash|\bdash|\bksh)$'; then
                    echo "${f}"
                fi
                ;;
        esac
    done
)

if [ "${#FILES[@]}" -eq 0 ]; then
    # Never pass by finding nothing. Phase 3 hit exactly this: an
    # all-files pre-commit run went green while demo/ was still
    # untracked, so the check appeared to hold while testing nothing.
    echo "ERROR: no shell scripts found under tools/ or demo/; the file" >&2
    echo "  selection above is broken, or this is not a git checkout." >&2
    exit 1
fi

echo "Running shellcheck over ${#FILES[@]} shell scripts in tools/ and demo/"
shellcheck -x "${FILES[@]}"
echo "shellcheck: clean"
