#!/bin/bash

# Assert that every required status check context in the exported
# develop ruleset (.github/exported-config/ruleset-*.json, archived by
# export-repo-config.yml) matches a job display name in
# .github/workflows/. The required checks are bound to workflow jobs
# purely by display-name string matching, and a required check whose
# name matches no job never reports -- which blocks every merge in the
# repository until an operator edits the ruleset by hand. This check
# converts that failure from "discovered when merges stop working"
# into a red smoke check. See
# docs/plans/PLAN-two-tier-ci-phase-03-merge-queue.md.
#
# Until the phase 3 ruleset change has been applied and re-exported,
# the exported rulesets contain no required_status_checks and this
# passes trivially.

set -e

cd "$(dirname "$0")/.."

fail=0
for ruleset in .github/exported-config/ruleset-*.json; do
    [ -e "${ruleset}" ] || continue
    while IFS= read -r context; do
        [ -z "${context}" ] && continue
        if ! grep -rqF "name: \"${context}\"" .github/workflows/; then
            echo "Required check '${context}' (${ruleset}) matches no job" >&2
            echo "name: in .github/workflows/ -- merges will block on a" >&2
            echo "check that never reports." >&2
            fail=1
        fi
    done < <(jq -r '.rules[]?
                    | select(.type == "required_status_checks")
                    | .parameters.required_status_checks[].context' \
                "${ruleset}")
done

if [ "${fail}" -eq 0 ]; then
    echo 'All required status check contexts match workflow job names.'
fi
exit "${fail}"
