#!/bin/bash

# Usage: file-pypi-storage-issue.sh threshold <report-file> <run-url>
#        file-pypi-storage-issue.sh broken <run-url>
#
# Called by the scheduled pypi-storage-check workflow. PyPI has no API to
# delete or yank a release, so pruning the kerbside-proxy project is a
# manual web-UI action (see RELEASE-SETUP.md) -- nothing will do it until
# someone is asked. A red entry in the Actions tab alerts nobody, so file
# or update a tracking issue instead. This mirrors
# tools/file-nightly-failure-issue.sh, including its dedupe by exact
# issue title so a recurring alarm comments on one issue rather than
# filing a new one every week.
#
# Two modes, because the two things worth saying are different. The
# "threshold" mode is news about the project: a budget is being
# approached and a human should prune. The "broken" mode is news about
# the monitor itself: the check could not run, so the silence from here
# on means nothing. That second case needs its own alarm precisely
# because this watchdog is designed to say nothing for years -- a
# silently broken monitor is indistinguishable from a healthy one, and
# the Actions tab that would show it red is the alerting mechanism this
# script exists to work around.
#
# Runs in a repository checkout; gh infers the repository from the git
# remote.

set -e

# file_or_comment <title> <new-issue-body> <existing-issue-comment>
file_or_comment() {
    local title="$1"
    local create_body="$2"
    local comment_body="$3"

    # The exact-title match is made in bash rather than by interpolating
    # ${title} into the jq program. Both call sites pass a literal today, so
    # nothing here is exploitable, but a jq program assembled by string
    # substitution is a trap for the next caller with a computed title -- a
    # quote or a backslash in it would rewrite the program rather than be
    # compared by it. --jq now only names fields, and never sees the title.
    local existing=''
    local number found
    while IFS=$'\t' read -r number found; do
        if [ "${found}" = "${title}" ]; then
            existing="${number}"
            break
        fi
    done < <(gh issue list --state open --search "in:title \"${title}\"" \
        --json number,title --jq '.[] | "\(.number)\t\(.title)"')

    if [ -n "${existing}" ]; then
        gh issue comment "${existing}" --body "${comment_body}"
        echo "Updated existing issue #${existing}."
    else
        gh issue create --title "${title}" --body "${create_body}"
        echo 'Filed a new tracking issue.'
    fi
}

mode="$1"

case "${mode}" in
    threshold)
        report_file="$2"
        run_url="$3"
        if [ -z "${report_file}" ] || [ -z "${run_url}" ]; then
            echo "usage: $0 threshold <report-file> <run-url>" >&2
            exit 1
        fi

        # -s rather than -f: tee creates the file even when the check
        # produced no stdout, so an existence test would happily file an
        # alarm containing an empty code fence. A contentless alarm is
        # worse than none, because it trains the reader to ignore the
        # issue -- so refuse to file it, loudly, where the failure
        # surfaces in the Actions tab instead.
        if [ ! -s "${report_file}" ]; then
            echo "report file missing or empty: ${report_file}" >&2
            exit 1
        fi

        report="$(cat "${report_file}")"

        file_or_comment \
            "kerbside-proxy PyPI storage threshold crossed" \
            "A weekly check of the kerbside-proxy PyPI project's storage \
budget has crossed a threshold: ${run_url}

\`\`\`
${report}
\`\`\`

PyPI has no API to delete or yank a release (Warehouse issue #12810 is
open and blocked), so pruning is a manual web-UI action. See
RELEASE-SETUP.md's \"Pruning dev releases\" section for the procedure --
deletion is irreversible, so read that before pruning anything. Close
this issue once the project is back under both thresholds." \
            "Still crossed: ${run_url}

\`\`\`
${report}
\`\`\`"
        ;;

    broken)
        run_url="$2"
        if [ -z "${run_url}" ]; then
            echo "usage: $0 broken <run-url>" >&2
            exit 1
        fi

        file_or_comment \
            "kerbside-proxy PyPI storage check is broken" \
            "The weekly kerbside-proxy PyPI storage check could not run: \
${run_url}

This is not a report that a threshold was crossed -- it is a report that
no threshold can currently be checked. The likely causes are a PyPI
outage (transient, and the next weekly run will clear it) or a change to
the PyPI JSON API's \`releases\` key, which
\`tools/check-pypi-storage.py\` depends on and which is the least
committed part of that API. If it is the latter, the PEP 691/700 Simple
API JSON view carries the same per-file size and upload-time fields.

This alarm exists because the check is expected to report nothing for
years at a time, so its silence cannot be taken as good news unless
something separately confirms it still runs. Close this issue once a
weekly run succeeds." \
            "Still broken: ${run_url}"
        ;;

    *)
        echo "usage: $0 threshold <report-file> <run-url>" >&2
        echo "       $0 broken <run-url>" >&2
        exit 1
        ;;
esac
