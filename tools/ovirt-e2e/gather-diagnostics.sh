#!/bin/bash
#
# Collect the oVirt lane's diagnostic bundle from the target guest, for
# the "Gather artifacts" step of functional-tests.yml.
#
# Usage:
#   tools/ovirt-e2e/gather-diagnostics.sh USER@HOST OUTDIR
#
# Produces OUTDIR/bundle.zip, always, and exits 0, always. Both of those
# are the point of this script rather than incidental to it.
#
# WHY THIS EXISTS: the step used to be four commands inline in the
# workflow, the first of which ran /srv/ovirt-gather-artifacts.sh on the
# guest. That script is delivered by the "Copy tools and config to
# target" step, which is several steps after "Build infrastructure", so
# any failure during provisioning meant the gather step died on
#
#   bash: /srv/ovirt-gather-artifacts.sh: No such file or directory
#   ##[error]Process completed with exit code 127
#
# and, because the step runs under `bash -e`, nothing after it ran. The
# upload that follows then found no bundle and failed too. Six
# consecutive merge-queue failures produced zero guest-side diagnostics
# that way, which is most of why shakenfist/kerbside#446 took as long to
# diagnose as it did. A gather step is worth having precisely on the runs
# where something has already gone wrong, so this one collects what it
# can and reports what it could not rather than failing.
#
# WHAT IT COLLECTS: the target-side bundle when the guest has the script
# to build one, and otherwise a fallback set gathered over ssh -- enough
# to tell a guest that never finished cloud-init from one that is up and
# healthy while something on the runner side is broken. gather.log
# records every command and its exit code either way, so an empty bundle
# still says why it is empty.
#
# ARTIFACTS ARE WORLD-DOWNLOADABLE for the full retention period, so this
# script collects system state only. The guest's cloud-init logs carry
# the CI ssh *public* key and the instance's network configuration and
# nothing else of interest; anything added here must clear the same bar
# as the kerbside-side artifact list in functional-tests.yml.

TARGET="$1"
OUTDIR="$2"

if [ -z "${TARGET}" ] || [ -z "${OUTDIR}" ]; then
    echo "usage: $0 USER@HOST OUTDIR" >&2
    exit 1
fi

# The runner's CI key, overridable so that this script can be exercised
# against a throwaway guest off a runner -- which is how its two paths
# were tested, and the only way they can be.
SSH_KEY="${SSH_KEY:-/srv/github/id_ci}"

SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=no
          -o UserKnownHostsFile=/dev/null -o BatchMode=yes
          -o ConnectTimeout=10 ${SSH_EXTRA_OPTS:-})

BUNDLE="${OUTDIR}/bundle"
LOG="${BUNDLE}/gather.log"

rm -rf "${BUNDLE}" "${OUTDIR}/bundle.zip"
mkdir -p "${BUNDLE}"

note() {
    echo "=== $* ===" >> "${LOG}"
}

# Run a command on the guest, putting its output in the bundle and its
# exit code in the log. Never propagates a failure: a guest which cannot
# answer one question can usually still answer the next one, and the
# whole point here is to come back with whatever it will give us.
remote() {
    local name="$1"
    shift

    note "${name}: $*"
    if timeout 120 ssh "${SSH_OPTS[@]}" "${TARGET}" "$@" \
            > "${BUNDLE}/${name}" 2>> "${LOG}"; then
        echo "  exit 0" >> "${LOG}"
    else
        echo "  exit $? (see ${name} and the stderr above)" >> "${LOG}"
    fi
}

note "gathering from ${TARGET} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# The guest-side bundle, when the guest has the script that builds it.
# Tested for rather than attempted blindly so that its absence reads as
# "provisioning did not get that far" in the log instead of as an error.
if timeout 60 ssh "${SSH_OPTS[@]}" "${TARGET}" \
        "test -f /srv/ovirt-gather-artifacts.sh" 2>> "${LOG}"; then
    note "building the target-side bundle"
    if timeout 600 ssh "${SSH_OPTS[@]}" "${TARGET}" \
            "bash /srv/ovirt-gather-artifacts.sh" >> "${LOG}" 2>&1 \
            && timeout 300 scp -rp "${SSH_OPTS[@]}" \
                "${TARGET}:/tmp/bundle.zip" "${BUNDLE}/target-bundle.zip" \
                >> "${LOG}" 2>&1; then
        (cd "${BUNDLE}" && unzip -q target-bundle.zip && rm target-bundle.zip) \
            >> "${LOG}" 2>&1
        echo "  target-side bundle collected" >> "${LOG}"
    else
        echo "  target-side bundle FAILED, falling back" >> "${LOG}"
        FALLBACK=yes
    fi
else
    note "no /srv/ovirt-gather-artifacts.sh on the guest"
    echo "  provisioning did not reach the step which delivers it" >> "${LOG}"
    FALLBACK=yes
fi

# The fallback set. Deliberately reaches for the things which separate
# the failure modes this lane actually has: a guest still inside
# cloud-init, a guest whose sshd is bouncing, a guest which is entirely
# healthy and is being managed by something that cannot talk to it (the
# Python version is in there because that is what #446 turned out to be).
if [ -n "${FALLBACK}" ]; then
    note "collecting the fallback set"

    remote cloud-init-status "sudo cloud-init status --long"
    remote cloud-init.log "sudo tail -n 5000 /var/log/cloud-init.log"
    remote cloud-init-output.log \
        "sudo tail -n 5000 /var/log/cloud-init-output.log"
    remote sshd.journal "sudo journalctl -u sshd --no-pager -n 500"
    remote systemd-failed "systemctl --failed --no-pager"
    remote uname "uname -a"
    remote python-version "python3 -V; ls -l /usr/bin/python3*"
    remote os-release "cat /etc/os-release"
    remote disk "df -h"
    remote memory "free -m"
    remote dmesg "sudo dmesg | tail -n 500"
fi

note "done"

# zip -r returns non-zero if it finds nothing to add, which would take the
# step down for the same reason the old inline commands did.
(cd "${OUTDIR}" && zip -qr bundle.zip bundle) || \
    echo "zip failed, see ${LOG}" >&2

exit 0
