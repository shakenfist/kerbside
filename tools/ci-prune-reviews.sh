#!/bin/bash -e

# Prune review marks made stale by pushes to develop and commit the
# regenerated review state back. Run by the prune-reviews workflow;
# mirrors the development repository's scripts/commit-audit-docs.sh
# landing pattern. Prune only ever removes marks, so this unsigned
# bot commit does not weaken the review attestations -- those live in
# the signed commits that introduced the stamps. See the steady state
# section of
# https://github.com/shakenfist/development/blob/main/docs/code-review-tracking.md

./tools/review-tracking.sh prune

if git diff --quiet -- .vscode/ REVIEWS.md; then
    echo "No stale review marks to prune."
    exit 0
fi

git config user.name 'shakenfist-bot'
git config user.email 'bot@shakenfist.com'

git add .vscode/ REVIEWS.md
git commit -m 'Prune stale review marks.

Automated commit by the prune-reviews workflow.'

# Another push may have landed while we ran; rebase our commit on top
# rather than failing the workflow.
git pull --rebase origin develop
git push origin develop
