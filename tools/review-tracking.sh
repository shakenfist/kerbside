#!/bin/bash

# Run the shared code review tracking helper by hand. Subcommands:
#
#   stamp   record blob SHAs for newly reviewed files, regen REVIEWS.md
#   prune   drop review marks for files changed since review, regen
#   regen   regenerate REVIEWS.md from current state
#   next    pick a random unreviewed in-scope file and open it
#   status  report effective review coverage against HEAD (read-only)
#
# These used to run automatically from git hooks (pre-commit,
# post-merge, post-checkout, post-rewrite), which made them fire
# confusingly in the middle of other git operations; in a clone they
# only run when invoked explicitly. Typical session: "prune" after a
# pull, "stamp" before committing review marks. On develop itself the
# prune-reviews workflow runs prune automatically after every push
# (via tools/ci-prune-reviews.sh). The implementation lives in the
# shakenfist/development repository; see
# https://github.com/shakenfist/development/blob/main/docs/code-review-tracking.md

set -e

repo_root="$(git rev-parse --show-toplevel)"

candidates=(
    "${SHAKENFIST_DEVELOPMENT:-}"
    "${repo_root}/../development"
    "${HOME}/src/shakenfist/development"
)

for candidate in "${candidates[@]}"; do
    script="${candidate}/scripts/review-tracking.py"
    if [ -n "${candidate}" ] && [ -x "${script}" ]; then
        cd "${repo_root}"
        exec "${script}" "$@"
    fi
done

echo 'Cannot find a shakenfist/development clone providing' >&2
echo 'scripts/review-tracking.py. Clone it next to this repository or' >&2
echo 'set SHAKENFIST_DEVELOPMENT to the path of an existing clone.' >&2
exit 1
