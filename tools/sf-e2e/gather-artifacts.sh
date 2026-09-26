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
# (which holds the test namespace key). Everything that is collected --
# journals, logs, the console.vv and sources.yaml alike -- then goes through
# one redaction pass over the whole output directory, followed by a check
# that nothing matching the secret shapes survived. libvirtd echoes the domain
# XML when it refuses a definition, and that XML carries the instance's SPICE
# password; an SF daemon may log a dict holding one. Redacting per file would
# leave whichever file the next change adds unredacted, so the pass is over
# the directory instead.
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

# Journals are unbounded in time: the primary is a single-use CI VM, so its
# whole journal is this run. A "--since" window measured back from the gather
# can expire before the failure it exists to capture, since the gather runs
# after every other step has had its turn.
journal() {
    local out="$1"
    shift
    # The journalctl arguments are ours and fixed, so expanding them on the
    # runner is the intent; the unit glob arrives already quoted for the
    # remote shell.
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "${BASE_USER}@${PRIMARY}" \
        "sudo journalctl --no-pager $*" \
        > "${OUTDIR}/${out}" 2>/dev/null || true
}

# The mint/console daemons, kept as their own files for greppability.
journal sf-api.journal -u sf-api
journal sf-console.journal -u sf-console

# The remaining SF daemons and libvirtd, which is where an instance that never
# starts actually fails. Matched by unit glob rather than by name: the units
# are templated per daemon (sf-cluster, sf-cleaner, sf-resources and the rest),
# so a hand-written list goes stale the next time one is added. The glob also
# matches sf-api and sf-console; that overlap is deliberate, because a glob
# only matches units systemd has loaded while a named -u matches the journal
# directly, so the named captures above survive a daemon that failed to load.
journal sf-daemons.journal -u '"sf-*"'
journal libvirtd.journal -u libvirtd -u virtqemud

# Redact the value, not the line: the line is often the error being
# collected. These artifacts are retained for 90 days and downloadable by
# anyone who can see the repository.
#
# SECRET_KEY is a password-ish key followed by its separator, in each of the
# spellings seen or plausible here: libvirt XML (passwd='...'), key=value,
# YAML (password: ...), a Python or JSON dict ('password': '...'), and a
# command line (--password ...). passwdValidTo is a timestamp and has no
# separator straight after "passwd", so it is not matched. The value may be
# empty, so every match gets REDACTED appended, which is what lets the check
# below treat any unredacted key as a failure.
SECRET_KEY="(passw(or)?d['\"]?[[:space:]]*[=:][[:space:]]*|--passw(or)?d[[:space:]]+)"
SECRET_VALUE="('[^']*'|\"[^\"]*\"|[^[:space:],}'\"]*)"

# The check's own spelling of the same shapes, written out separately on
# purpose: were it derived from SECRET_KEY, narrowing SECRET_KEY would narrow
# the check with it, and the check would only ever confirm the redaction
# agreed with itself.
LEAK_SHAPE="(--password|--passwd)[[:space:]=]|(password|passwd)[\"']?[[:space:]]*[=:]"

LEAKED=0
while IFS= read -r -d '' f; do
    sed -i -E "s/${SECRET_KEY}${SECRET_VALUE}/\1REDACTED/gI" "${f}"

    # A redaction that silently stops matching looks exactly like one that
    # worked (tools/demo/redact-artifacts.sh learned this first). Remove
    # every redacted key whose REDACTED ends cleanly (REDACTED'rest' is a
    # quoted value the redaction split, not a redacted one), then look for
    # any key-and-separator left over.
    # Prose ("spice password not supported") has no separator and is not
    # flagged, which matters: a false alarm deletes a journal. Report
    # the file name only: printing the match would copy the secret into the
    # workflow log, which is as public as the artifact. The file is deleted
    # rather than the gather failed, because the upload step runs regardless
    # and the other files are still worth having.
    if sed -E "s/(${LEAK_SHAPE})[[:space:]]*REDACTED([^[:alnum:]'\"]|$)/ /gI" \
            "${f}" \
            | grep -qiE "${LEAK_SHAPE}"; then
        echo "[sf-e2e] ERROR: a secret survived redaction in" \
            "$(basename "${f}"); not uploading it" >&2
        rm -f "${f}"
        LEAKED=1
    fi
done < <(find "${OUTDIR}" -type f -print0)

echo "[sf-e2e] gathered artifacts into ${OUTDIR}"
ls -la "${OUTDIR}" || true

if [ "${LEAKED}" -ne 0 ]; then
    echo "[sf-e2e] fix the redaction patterns rather than deleting this" \
        "check" >&2
    exit 1
fi
