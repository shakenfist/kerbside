#!/bin/bash
# Gather sf-e2e artifacts from the SF primary onto the runner.
#
# Runs ON the runner. Collects kerbside logs, gunicorn logs, ryll
# stdout/stderr, the console.vv, sources.yaml, and the SF journald logs for
# sf-api / sf-console into a local directory for upload-artifact.
#
# SECURITY: NEVER collects the SF token JWT, the auth seed, or instance.env
# (which holds the test namespace key). The console.vv (a kerbside
# consoletoken, as the direct-qemu lane already uploads) and sources.yaml
# (whose password is the well-known CI system key) are included.
#
# Usage: gather-artifacts.sh BASE_USER PRIMARY OUTDIR

set -uo pipefail

BASE_USER="${1:?Usage: $0 BASE_USER PRIMARY OUTDIR}"
PRIMARY="${2:?Usage: $0 BASE_USER PRIMARY OUTDIR}"
OUTDIR="${3:?Usage: $0 BASE_USER PRIMARY OUTDIR}"

SSH_OPTS=(-i /srv/github/id_ci -o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null)

mkdir -p "${OUTDIR}"

# Best-effort file copies (a missing file must not fail the gather).
for f in \
    run/kerbside.log \
    run/kerbside.log.gunicorn-access \
    run/kerbside.log.gunicorn-error \
    run/ryll.stdout \
    run/ryll.stderr \
    run/console.vv \
    run/sextant-serial.log \
    run/sources.yaml ; do
    scp "${SSH_OPTS[@]}" \
        "${BASE_USER}@${PRIMARY}:/tmp/sf-e2e/${f}" \
        "${OUTDIR}/$(basename "${f}")" 2>/dev/null || true
done

# SF journald for the mint/console daemons (best effort).
ssh "${SSH_OPTS[@]}" "${BASE_USER}@${PRIMARY}" \
    'sudo journalctl -u sf-api --no-pager --since "-30 min"' \
    > "${OUTDIR}/sf-api.journal" 2>/dev/null || true
ssh "${SSH_OPTS[@]}" "${BASE_USER}@${PRIMARY}" \
    'sudo journalctl -u sf-console --no-pager --since "-30 min"' \
    > "${OUTDIR}/sf-console.journal" 2>/dev/null || true

echo "[sf-e2e] gathered artifacts into ${OUTDIR}"
ls -la "${OUTDIR}" || true
