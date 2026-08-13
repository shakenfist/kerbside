#!/bin/bash

# Usage: file-nightly-failure-issue.sh <lane> <run-url>
#
# Called by the scheduled smoke lanes when a nightly run fails. The nightly
# schedules are load-bearing: they bound the accepted risk that the merge
# queue never re-runs the direct-qemu and sf-e2e lanes against the merged
# tree. A red entry in the Actions tab alerts nobody, so file or update a
# tracking issue instead, mirroring the fleet's consistency-audit pattern.
# Runs in a repository checkout; gh infers the repository from the git
# remote.

set -e

lane="$1"
run_url="$2"
if [ -z "${lane}" ] || [ -z "${run_url}" ]; then
    echo "usage: $0 <lane> <run-url>" >&2
    exit 1
fi

title="Nightly ${lane} lane failing"

existing=$(gh issue list --state open --search "in:title \"${title}\"" \
    --json number,title \
    --jq ".[] | select(.title == \"${title}\") | .number" | head -1)

if [ -n "${existing}" ]; then
    gh issue comment "${existing}" --body "Still failing: ${run_url}"
    echo "Updated existing issue #${existing}."
else
    gh issue create --title "${title}" --body "The nightly ${lane} run \
failed: ${run_url}

The nightly schedule bounds the accepted two-tier CI risk that the
merge queue does not re-run this lane against the merged tree, so
a red nightly means merged-tree coverage of the proxy path has
stopped. Close this issue when the nightly is green again."
    echo 'Filed a new tracking issue.'
fi
