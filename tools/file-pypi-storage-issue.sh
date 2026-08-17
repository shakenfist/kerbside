#!/bin/bash

# Usage: file-pypi-storage-issue.sh <report-file> <run-url>
#
# Called by the scheduled pypi-storage-check workflow when
# check-pypi-storage.py reports that a threshold has been crossed. PyPI
# has no API to delete or yank a release, so pruning the kerbside-proxy
# project is a manual web-UI action (see RELEASE-SETUP.md) -- nothing
# will do it until someone is asked. A red entry in the Actions tab
# alerts nobody, so file or update a tracking issue instead. This
# mirrors tools/file-nightly-failure-issue.sh, including its dedupe by
# exact issue title so a recurring alarm comments on one issue rather
# than filing a new one every week.
# Runs in a repository checkout; gh infers the repository from the git
# remote.

set -e

report_file="$1"
run_url="$2"
if [ -z "${report_file}" ] || [ -z "${run_url}" ]; then
    echo "usage: $0 <report-file> <run-url>" >&2
    exit 1
fi

# -s rather than -f: tee creates the file even when the check produced no
# stdout, so an existence test would happily file an alarm containing an
# empty code fence. A contentless alarm is worse than none, because it
# trains the reader to ignore the issue -- so refuse to file it, loudly,
# where the failure surfaces in the Actions tab instead.
if [ ! -s "${report_file}" ]; then
    echo "report file missing or empty: ${report_file}" >&2
    exit 1
fi

title="kerbside-proxy PyPI storage threshold crossed"

existing=$(gh issue list --state open --search "in:title \"${title}\"" \
    --json number,title \
    --jq ".[] | select(.title == \"${title}\") | .number" | head -1)

report="$(cat "${report_file}")"

if [ -n "${existing}" ]; then
    gh issue comment "${existing}" --body "Still crossed: ${run_url}

\`\`\`
${report}
\`\`\`"
    echo "Updated existing issue #${existing}."
else
    gh issue create --title "${title}" --body "A weekly check of the kerbside-proxy \
PyPI project's storage budget has crossed a threshold: ${run_url}

\`\`\`
${report}
\`\`\`

PyPI has no API to delete or yank a release (Warehouse issue #12810 is
open and blocked), so pruning is a manual web-UI action. See
RELEASE-SETUP.md's \"Pruning dev releases\" section for the procedure --
deletion is irreversible, so read that before pruning anything. Close
this issue once the project is back under both thresholds."
    echo 'Filed a new tracking issue.'
fi
