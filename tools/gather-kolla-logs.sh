#!/bin/bash
#
# Collect the OpenStack lane's log bundle from its Kolla-Ansible guest, for
# the "Collect logs" step of functional-tests.yml.
#
# Usage:
#   tools/gather-kolla-logs.sh USER@HOST OUTDIR
#
# Produces OUTDIR/bundle.zip, always, and exits 0, always, like
# tools/ovirt-e2e/gather-diagnostics.sh, whose header explains why a gather
# step must not fail.
#
# WHY THIS EXISTS: the step used to be three inline ssh/scp commands with
# no connect timeout. When "Setup test environment" failed because the
# under-cloud refused the guest (a capacity 507), there was no guest at
# 10.0.2.2: the first ssh hung for over two minutes, failed with
# "Connection timed out", and the upload after it then failed on a missing
# /tmp/bundle.zip. Each of the nine such failures in October 2026 reported
# three red steps for one cause, and the two extra ones sent readers to the
# wrong step. Now an unreachable guest is probed in ten seconds and
# reported as a warning, and the bundle says why it holds no guest logs.
#
# WHAT IT COLLECTS: what kerbside-patches' tools/gather-logs puts in the
# guest's /tmp/bundle.zip, plus the Kerbside Tempest logs and tempest.conf
# when a Tempest run got far enough to leave them. gather.log records each
# command and its exit code.

TARGET="$1"
OUTDIR="$2"

if [ -z "${TARGET}" ] || [ -z "${OUTDIR}" ]; then
    echo "usage: $0 USER@HOST OUTDIR" >&2
    exit 1
fi

# Overridable so this script can be exercised against a throwaway guest
# off a runner, as gather-diagnostics.sh's are.
SSH_KEY="${SSH_KEY:-/srv/github/id_ci}"
read -r -a SSH_EXTRA_OPTS_ARRAY <<< "${SSH_EXTRA_OPTS:-}"
SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null -o BatchMode=yes
          -o ConnectTimeout=10 "${SSH_EXTRA_OPTS_ARRAY[@]}")

BUNDLE="${OUTDIR}/bundle"
LOG="${BUNDLE}/gather.log"

rm -rf "${BUNDLE}" "${OUTDIR}/bundle.zip"
mkdir -p "${BUNDLE}"

note() {
    echo "=== $* ===" >> "${LOG}"
}

# Run a command on the guest, logging its output and exit code. Never
# propagates a failure.
remote() {
    local limit="$1"
    shift

    note "$*"
    local rc=0
    timeout "${limit}" ssh "${SSH_OPTS[@]}" "${TARGET}" "$@" >> "${LOG}" 2>&1 || rc=$?
    echo "  exit ${rc}" >> "${LOG}"
    return "${rc}"
}

note "gathering from ${TARGET} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! remote 30 true; then
    echo "  the guest is unreachable: provisioning failed before it existed" >> "${LOG}"
    echo "  or before it accepted ssh, so there are no guest logs" >> "${LOG}"
    echo "::warning::${TARGET} is unreachable, so the bundle holds no guest logs; see the first failed step"
else
    remote 900 'cd /srv/shakenfist/kerbside-patches && sudo ./tools/gather-logs'
    remote 300 'if [ -d /srv/kerbside-tempest ]; then sudo zip -r /tmp/bundle.zip /srv/kerbside-tempest/logs /srv/kerbside-tempest/tempest/etc/tempest.conf; fi'
    note "copying /tmp/bundle.zip"
    if timeout 300 scp -p "${SSH_OPTS[@]}" "${TARGET}:/tmp/bundle.zip" \
            "${BUNDLE}/guest-bundle.zip" >> "${LOG}" 2>&1; then
        echo "  exit 0" >> "${LOG}"
        # Unpacked, so the artifact is one zip rather than a zip in a zip;
        # kept packed if unzip fails, which loses nothing.
        (cd "${BUNDLE}" && unzip -q guest-bundle.zip && rm guest-bundle.zip) \
            >> "${LOG}" 2>&1
    else
        echo "  exit $?: no guest bundle, see the gather-logs output above" >> "${LOG}"
    fi
fi

note "done"

# zip -r returns non-zero if it finds nothing to add, which would fail the
# step for the same reason the old inline commands did.
(cd "${OUTDIR}" && zip -qr bundle.zip bundle) || \
    echo "zip failed, see ${LOG}" >&2

exit 0
