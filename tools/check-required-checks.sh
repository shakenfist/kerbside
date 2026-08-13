#!/bin/bash

# Assert that every required status check context in the exported develop
# ruleset (.github/exported-config/ruleset-*.json, archived by
# export-repo-config.yml) matches a job display name in .github/workflows/. The
# required checks are bound to workflow jobs purely by display-name string
# matching, and a required check whose name matches no job never reports --
# which blocks every merge in the repository until an operator edits the
# ruleset by hand. This check converts that failure from "discovered when
# merges stop working" into a red smoke check.
#
# The match is anchored to job-level indentation (four spaces) so a
# step name can never satisfy it, and accepts unquoted, single- or
# double-quoted YAML names. Parsing uses python3 rather than jq so the
# script has no dependencies beyond the runner image.
#
# If the exported rulesets contain no required_status_checks, this
# passes trivially.

set -e

cd "$(dirname "$0")/.."

fail=0
for ruleset in .github/exported-config/ruleset-*.json; do
    [ -e "${ruleset}" ] || continue
    while IFS= read -r context; do
        [ -z "${context}" ] && continue
        # The single quotes are deliberate: this is a sed character
        # class of regex metacharacters, not a shell expression.
        # shellcheck disable=SC2016
        esc=$(printf '%s' "${context}" | sed -e 's/[][\.*^$(){}?+|]/\\&/g')
        if ! grep -rqE "^    name: [\"']?${esc}[\"']?[[:space:]]*$" \
                .github/workflows/; then
            echo "Required check '${context}' (${ruleset}) matches no job" >&2
            echo "name: in .github/workflows/ -- merges will block on a" >&2
            echo "check that never reports." >&2
            fail=1
        fi
    done < <(python3 -c "
import json
import sys

with open(sys.argv[1]) as f:
    ruleset = json.load(f)
for rule in ruleset.get('rules') or []:
    if rule.get('type') == 'required_status_checks':
        for check in rule['parameters']['required_status_checks']:
            print(check['context'])
" "${ruleset}")
done

if [ "${fail}" -eq 0 ]; then
    echo 'All required status check contexts match workflow job names.'
fi
exit "${fail}"
