#!/bin/bash
# Scrub secrets from the demo lane's artifact directory before upload.
#
# CI artifacts are downloadable by anyone who can see the repository, so
# this runs unconditionally, and it runs AFTER log collection -- not
# before it, which is where the first version of this went wrong.
# Redaction ordered ahead of `docker compose logs` cannot scrub anything
# the logs contain, so the ordering is load-bearing rather than
# incidental. Keep it last.
#
# Two secrets, from two different places:
#
#   - `password=` in a .vv file is a live console token. kerbside/api.py
#     mints one per session; it is short-lived, but while it lasts it is
#     a bearer credential for a console.
#   - MariaDB prints the root password it generates for
#     MARIADB_RANDOM_ROOT_PASSWORD to its own log, as `GENERATED ROOT
#     PASSWORD: ...` (demo/docker-compose.yml:17). That one is
#     genuinely throwaway -- the database is never published outside the
#     compose network and the container is destroyed with the job -- but
#     a credential in a downloadable artifact is worth removing whether
#     or not it is reachable.
#
# The verification pass at the end is the point of the script. A
# redaction that silently stops matching, because an upstream message
# changed wording, looks exactly like a redaction that worked.

set -euo pipefail

ARTIFACT_DIR="${1:-/tmp/kerbside-demo-lane}"

if [ ! -d "${ARTIFACT_DIR}" ]; then
    echo "ERROR: ${ARTIFACT_DIR} does not exist; nothing to redact, which" >&2
    echo "  means the lane did not get far enough to produce artifacts." >&2
    exit 1
fi

# Every file under the directory, not just the *.vv files. The upload
# step's `path:` includes `logs/` and `*.log` as well, and `ryll
# --verbose` is handed the .vv via --file, so a token could plausibly
# reach a log even though grepping the proxy sources found no ticket
# logging today. Redacting a file that never contained a secret costs
# nothing; missing one that did is the whole risk.
redact_everywhere() {
    local pattern="$1" replacement="$2" what="$3" f found=0
    # -l first so sed only rewrites files that actually match, and -Z/-0
    # so a path containing a space cannot split. Filenames are reported,
    # never the matching line: printing the match would copy the secret
    # into the workflow log, which is as public as the artifact itself.
    while IFS= read -r -d '' f; do
        sed -i "s/${pattern}.*/${replacement}/" "${f}"
        echo "  redacted ${what} in ${f}"
        found=1
    done < <(grep -rlZ "${pattern}" "${ARTIFACT_DIR}" 2> /dev/null || true)
    if [ "${found}" -eq 0 ]; then
        echo "  no ${what} found"
    fi
}

echo "redact-artifacts: scrubbing ${ARTIFACT_DIR}"
redact_everywhere '^password=' 'password=REDACTED' 'a console token'
redact_everywhere 'GENERATED ROOT PASSWORD: ' \
    'GENERATED ROOT PASSWORD: REDACTED' 'a generated database password'

# Names only, never the matching line: printing the match would copy the
# secret into the workflow log, which is as public as the artifact.
residual_files() {
    grep -rl "$1" "${ARTIFACT_DIR}" 2> /dev/null | while read -r f; do
        if grep "$1" "${f}" | grep -qv 'REDACTED'; then
            echo "  ${f}"
        fi
    done
}

RESIDUAL=0

CONSOLE_LEFT="$(residual_files '^password=')"
if [ -n "${CONSOLE_LEFT}" ]; then
    echo "ERROR: a live console token survived redaction in:" >&2
    echo "${CONSOLE_LEFT}" >&2
    RESIDUAL=1
fi

DB_LEFT="$(residual_files 'GENERATED ROOT PASSWORD: ')"
if [ -n "${DB_LEFT}" ]; then
    echo "ERROR: a generated database password survived redaction in:" >&2
    echo "${DB_LEFT}" >&2
    RESIDUAL=1
fi

if [ "${RESIDUAL}" -ne 0 ]; then
    echo "" >&2
    echo "Refusing to let the upload proceed with a secret in it. Fix the" >&2
    echo "  patterns above rather than deleting this check." >&2
    exit 1
fi

echo "redact-artifacts: no secrets remain in ${ARTIFACT_DIR}"
