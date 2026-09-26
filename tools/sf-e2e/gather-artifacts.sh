#!/bin/bash
# Gather sf-e2e artifacts from the SF primary onto the runner.
#
# Runs ON the runner. Collects kerbside logs, gunicorn logs, ryll
# stdout/stderr, the console.vv, sources.yaml, and the SF journald logs for
# sf-api / sf-console, the rest of the SF daemons, and libvirtd into a local
# directory for upload-artifact.
#
# The SF daemon and libvirtd journals are here because an instance that never
# starts leaves no trace in sf-api: the domain is defined by the per-node
# daemons and refused by libvirt, so a failure like shakenfist/shakenfist#4280
# ("spice graphics are not supported with this QEMU") was undiagnosable from a
# failed run's own artifacts. See shakenfist/kerbside#482.
#
# SECURITY: NEVER collects the SF token JWT, the auth seed, or instance.env
# (which holds the test namespace key). The console.vv (a kerbside
# consoletoken, as the direct-qemu lane already uploads) and sources.yaml
# (whose password is the well-known CI system key) are included. libvirtd
# echoes the domain XML when it refuses a definition, and that XML carries the
# instance's SPICE password, so both new journals are redacted on the way out
# rather than trusted to be clean.
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

# The remaining SF daemons and libvirtd, which is where an instance that never
# starts actually fails. Matched by unit glob rather than by name: the units
# are templated per daemon (sf-cluster, sf-cleaner, sf-resources and the rest),
# so a hand-written list goes stale the next time one is added.
#
# Redaction is not optional here. A libvirt refusal quotes the domain XML back,
# and that XML carries <graphics ... passwd='...'> for the instance's SPICE
# console. These artifacts are retained for 90 days and downloadable by anyone
# who can see the repository, so strip the value rather than the whole line --
# the line is the error being collected.
redact() {
    sed -E "s/(passwd=|password=)('[^']*'|\"[^\"]*\"|[^[:space:]]+)/\1REDACTED/g"
}

ssh "${SSH_OPTS[@]}" "${BASE_USER}@${PRIMARY}" \
    'sudo journalctl -u "sf-*" --no-pager --since "-30 min"' \
    2>/dev/null | redact > "${OUTDIR}/sf-daemons.journal" || true
ssh "${SSH_OPTS[@]}" "${BASE_USER}@${PRIMARY}" \
    'sudo journalctl -u libvirtd -u virtqemud --no-pager --since "-30 min"' \
    2>/dev/null | redact > "${OUTDIR}/libvirtd.journal" || true

echo "[sf-e2e] gathered artifacts into ${OUTDIR}"
ls -la "${OUTDIR}" || true
