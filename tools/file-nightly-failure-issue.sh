#!/bin/bash

# Usage: file-nightly-failure-issue.sh <lane> <run-url>
#
# Called by a lane whose run against develop failed -- the nightly cron
# in every case, and for sf-e2e also a conductor periodic dispatch of
# develop. Those runs are load-bearing: the merge queue never re-runs the
# direct-qemu and sf-e2e lanes against the merged tree, and the oVirt and
# OpenStack cloud lanes run nowhere else at all. A red entry in the
# Actions tab alerts nobody, so file or update a tracking issue instead,
# mirroring the fleet's consistency-audit pattern.
# Runs in a repository checkout; gh infers the repository from the git
# remote.
#
# The issue title is derived from the lane alone, deliberately: a cron
# failure and a dispatch failure in the same period must converge on one
# issue with a comment trail rather than racing to create two.

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
    gh issue create --title "${title}" --body "A ${lane} run against \
develop failed: ${run_url}

Pull request CI never runs this lane against develop itself, so a red
run here means that coverage of develop has stopped. Close this issue
when the lane is green again."
    echo 'Filed a new tracking issue.'
fi
