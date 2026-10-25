#!/bin/bash
# End-to-end proof that replacing or expiring a guest's SPICE password does
# not disturb a client that is already connected through the proxy, while a
# new connection presenting the old password is refused.
#
# A source that mints a SPICE password per session replaces the password the
# hypervisor holds whenever it mints again, and lets it expire. Both happen
# by QMP: set_password (with no `connected` argument, as oVirt and Proxmox
# call it) and expire_password. qemu applies a password only when a channel
# links, so established channels should survive both. This measures that on
# a real qemu, through the real daemon, API, MariaDB and Rust proxy:
#
#   1. Bring up an isolated lane (lane-up.sh) with a ryll session through
#      the proxy, and record the SPICE channels qemu holds open for it.
#   2. set_password with a new password. After SETTLE_SECONDS, the session
#      must still be up (see assert_session_up).
#   3. A fresh session through the proxy must be refused. The lane's static
#      source still hands the proxy the original ticket, so the fresh session
#      presents the old password, which qemu must reject.
#   4. expire_password `now`. After SETTLE_SECONDS, the session must still be
#      up, and a fresh session must again be refused.
#   5. Positive control: expire_password `never`, then a ryll connected
#      straight to qemu with the new password must get a display. This shows
#      the refusals in 3 and 4 came from the password, not from qemu
#      refusing everyone. spice-server drops its existing client when a new
#      one links, so this runs last.
#
# "Still up" is asserted three ways, all of which must hold: the ryll process
# is alive (headless ryll exits when its session ends); qemu's query-spice
# lists exactly the channels it listed before, down to each connection's
# client port, so no channel was dropped or re-established; and ryll's
# control socket reports a surface and returns a screenshot (smoke-client.py).
#
# "Refused" is asserted on the proxy's own record of the backend leg: the
# proxy logs "hypervisor connection failed" with the SPICE link error
# PermissionDenied when qemu rejects the ticket. The fresh ryll must also exit
# by itself within REFUSAL_DEADLINE, and qemu must still list only the first
# session's channels.
#
# The new password is generated into an owner-only file and passed to
# qmp-client.py by path, so it never appears in a command line or a log.
# The collected artifacts are searched for it on exit, and the run fails if
# any holds it, since the positive control's ryll runs verbosely with it.
#
# Self-contained, like verify-terminate-live.sh: its own WORKDIR, torn down on
# exit, with logs stashed in ROTATION_ARTIFACTS for CI upload. Ports are the
# lane defaults, so it must not run alongside another lane. Requires the same
# prerequisites as lane-up.sh (qemu, the Sextant qcow2, MariaDB, ryll) plus a
# resolvable kerbside-proxy binary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Isolated from the scenario lane's /tmp/kerbside-ci.
export WORKDIR="${ROTATION_WORKDIR:-/tmp/kerbside-rotation}"
export QEMU_QMP_SOCK="${WORKDIR}/qmp.sock"

CONSOLE_SOURCE="${CONSOLE_SOURCE:-direct-qemu-lab}"
CONSOLE_UUID="${CONSOLE_UUID:-6f4e2c1a-0000-0000-0000-000000000001}"
API_PORT="${API_PORT:-13002}"
SPICE_PORT="${SPICE_PORT:-5910}"
KERBSIDE_LOG="${WORKDIR}/kerbside.log"
RYLL_SOCK="${WORKDIR}/ryll-ci.sock"
RYLL_PID_FILE="${WORKDIR}/ryll.pid"
PASSWORD_FILE="${WORKDIR}/new-spice-password"
SMOKE_LOG="${WORKDIR}/smoke-client.log"
SETTLE_SECONDS="${SETTLE_SECONDS:-10}"
REFUSAL_DEADLINE="${REFUSAL_DEADLINE:-30}"

# The proxy's log line for a failed backend leg, and the SPICE link error
# qemu answers a wrong or expired ticket with (rust/kerbside-proxy/src/
# backend.rs record_connect_failure; ryll's link.rs "Authentication failed").
REFUSAL_LINE='hypervisor connection failed'
REFUSAL_CAUSE='PermissionDenied'

ROTATION_ARTIFACTS="${ROTATION_ARTIFACTS:-/tmp/rotation-artifacts}"
CONTROL_PID=''
cleanup() {
    local rc=$?
    if [ -n "${CONTROL_PID}" ]; then
        kill "${CONTROL_PID}" 2>/dev/null || true
    fi
    if [ -d "${WORKDIR}" ]; then
        mkdir -p "${ROTATION_ARTIFACTS}"
        for f in "${WORKDIR}"/kerbside.log* "${WORKDIR}"/ryll-*.std* \
                 "${WORKDIR}"/sextant-serial.log "${SMOKE_LOG}"; do
            if [ -f "${f}" ]; then
                cp "${f}" "${ROTATION_ARTIFACTS}/" 2>/dev/null || true
            fi
        done
        if [ -s "${PASSWORD_FILE}" ]; then
            local leaked
            leaked=$(grep -rlF -f "${PASSWORD_FILE}" "${ROTATION_ARTIFACTS}" || true)
            if [ -n "${leaked}" ]; then
                while read -r f; do
                    echo "ERROR: the new SPICE password appears in ${f}; removed it" >&2
                    rm -f "${f}"
                done <<< "${leaked}"
                rc=1
            fi
        fi
    fi
    WORKDIR="${WORKDIR}" "${SCRIPT_DIR}/lane-down.sh" || true
    exit "${rc}"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    echo "  kerbside daemon/proxy log (last 60 lines):" >&2
    tail -60 "${KERBSIDE_LOG}" >&2 || true
    exit 1
}

indent() {
    sed 's/^/    /'
}

qmp() {
    python3 "${SCRIPT_DIR}/qmp-client.py" --socket "${QEMU_QMP_SOCK}" "$@"
}

# Lines in the proxy log recording a backend leg qemu refused for its ticket.
count_refusals() {
    grep -F "${REFUSAL_LINE}" "${KERBSIDE_LOG}" 2>/dev/null \
        | grep -cF "${REFUSAL_CAUSE}" || true
}

assert_session_up() {
    local label="$1"
    local channels

    if ! kill -0 "${RYLL_PID}" 2>/dev/null; then
        fail "${label}: ryll (pid ${RYLL_PID}) has exited; its session ended"
    fi

    channels="$(qmp spice-channels)" || fail "${label}: query-spice failed"
    if [ "${channels}" != "${BASELINE_CHANNELS}" ]; then
        echo "  channels before:" >&2
        indent <<< "${BASELINE_CHANNELS}" >&2
        echo "  channels now:" >&2
        indent <<< "${channels}" >&2
        fail "${label}: qemu's SPICE channels changed"
    fi

    if ! python3 "${SCRIPT_DIR}/smoke-client.py" "${RYLL_SOCK}" 2>&1 \
            | tee -a "${SMOKE_LOG}"; then
        fail "${label}: ryll's control socket did not report a live display"
    fi
    echo "[verify-rotation] PASS ${label}: session up, same $(echo "${channels}" | wc -l) channels"
}

# Fetch a fresh .vv (and so a fresh console token and session) from the API
# and connect ryll with it. The static source hands the proxy the original
# ticket, so qemu must refuse the backend leg.
assert_fresh_session_refused() {
    local label="$1"
    local vv="${WORKDIR}/fresh-${label}.vv"
    local before after status rc

    before="$(count_refusals)"
    status="$(curl \
        --silent \
        --output "${vv}" \
        --write-out '%{http_code}' \
        --header "Authorization: Bearer ${JWT_TOKEN}" \
        "${VV_URL}")"
    if [ "${status}" != '200' ]; then
        fail "${label}: fresh .vv fetch returned HTTP ${status}"
    fi

    echo "[verify-rotation] ${label}: connecting a fresh ryll session with the old password"
    rc=0
    timeout "${REFUSAL_DEADLINE}" \
        ryll --verbose --headless --file "${vv}" \
        > "${WORKDIR}/ryll-fresh-${label}.stdout" \
        2> "${WORKDIR}/ryll-fresh-${label}.stderr" || rc=$?
    if [ "${rc}" -eq 124 ]; then
        fail "${label}: the fresh ryll session was still running after ${REFUSAL_DEADLINE}s"
    fi

    after="$(count_refusals)"
    if [ "${after}" -le "${before}" ]; then
        echo "  fresh ryll stderr (last 20 lines):" >&2
        tail -20 "${WORKDIR}/ryll-fresh-${label}.stderr" >&2 || true
        fail "${label}: the proxy logged no '${REFUSAL_LINE}' with ${REFUSAL_CAUSE}"
    fi
    echo "[verify-rotation] PASS ${label}: qemu refused the old password" \
         "(ryll exit ${rc}, ${REFUSAL_CAUSE} logged by the proxy)"
}

# ── Bring up the lane and record the session's channels ──────────────────────

echo "[verify-rotation] Bringing up an isolated Rust-proxy lane in ${WORKDIR}"
"${SCRIPT_DIR}/lane-up.sh"

if [ ! -S "${QEMU_QMP_SOCK}" ]; then
    fail "qemu's QMP socket was not created at ${QEMU_QMP_SOCK}"
fi
QMP_MODE="$(stat -c '%a' "${QEMU_QMP_SOCK}")"
if [ "${QMP_MODE}" != '600' ]; then
    fail "qemu's QMP socket has mode ${QMP_MODE}, not 600"
fi

RYLL_PID="$(cat "${RYLL_PID_FILE}")"
TOKEN_FILE="${WORKDIR}/kerbside-api-token.txt"
if [ ! -f "${TOKEN_FILE}" ]; then
    fail "API token not found: ${TOKEN_FILE}"
fi
JWT_TOKEN="$(cat "${TOKEN_FILE}")"
VV_URL="http://127.0.0.1:${API_PORT}/console/proxy/${CONSOLE_SOURCE}/${CONSOLE_UUID}/console.vv"

# Wait for the display before taking the baseline, so the baseline holds
# every channel ryll opens.
if ! python3 "${SCRIPT_DIR}/smoke-client.py" "${RYLL_SOCK}" 2>&1 | tee -a "${SMOKE_LOG}"; then
    fail "the first session never reported a display"
fi
BASELINE_CHANNELS="$(qmp spice-channels)" || fail "query-spice failed"
if [ -z "${BASELINE_CHANNELS}" ]; then
    fail "qemu lists no SPICE channels for the connected session"
fi
echo "[verify-rotation] baseline: qemu holds $(echo "${BASELINE_CHANNELS}" | wc -l) SPICE channels:"
indent <<< "${BASELINE_CHANNELS}"
# channel-type 1 is main and 2 is display (spice-protocol's SPICE_CHANNEL_*).
for want in 1 2; do
    if ! echo "${BASELINE_CHANNELS}" | awk '{print $2}' | grep -qx "${want}"; then
        fail "the baseline has no channel of type ${want}"
    fi
done

# ── Replace the password ──────────────────────────────────────────────────────

(umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "${PASSWORD_FILE}")
qmp set-spice-password --password-file "${PASSWORD_FILE}" || fail "set_password failed"
echo "[verify-rotation] waiting ${SETTLE_SECONDS}s after set_password"
sleep "${SETTLE_SECONDS}"
assert_session_up 'after set_password'

assert_fresh_session_refused 'after-set-password'
assert_session_up 'after the refused session'

# ── Expire the password ───────────────────────────────────────────────────────

qmp expire-spice-password --time now || fail "expire_password failed"
echo "[verify-rotation] waiting ${SETTLE_SECONDS}s after expire_password"
sleep "${SETTLE_SECONDS}"
assert_session_up 'after expire_password'

assert_fresh_session_refused 'after-expire-password'
assert_session_up 'after the second refused session'

# ── Positive control: the new password works once it no longer expires ──────

qmp expire-spice-password --time never || fail "expire_password never failed"
DIRECT_VV="${WORKDIR}/direct-new-password.vv"
CONTROL_SOCK="${WORKDIR}/ryll-control.sock"
(
    umask 077
    {
        printf '[virt-viewer]\ntype=spice\nhost=127.0.0.1\nport=%s\n' "${SPICE_PORT}"
        printf 'password=%s\n' "$(cat "${PASSWORD_FILE}")"
    } > "${DIRECT_VV}"
)
echo "[verify-rotation] connecting ryll straight to qemu with the new password"
ryll --verbose --headless --file "${DIRECT_VV}" --control-socket "${CONTROL_SOCK}" \
    > "${WORKDIR}/ryll-control.stdout" 2> "${WORKDIR}/ryll-control.stderr" &
CONTROL_PID=$!
DEADLINE=$(( $(date +%s) + 30 ))
while [ ! -S "${CONTROL_SOCK}" ]; do
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "  control ryll stderr (last 20 lines):" >&2
        tail -20 "${WORKDIR}/ryll-control.stderr" \
            | grep -vF -f "${PASSWORD_FILE}" >&2 || true
        fail "ryll with the new password never opened its control socket"
    fi
    sleep 0.5
done
if ! python3 "${SCRIPT_DIR}/smoke-client.py" "${CONTROL_SOCK}" 2>&1 | tee -a "${SMOKE_LOG}"; then
    fail "ryll with the new password did not get a display"
fi
echo "[verify-rotation] PASS positive control: qemu accepts the new password"

echo "[verify-rotation] a connected session survives set_password and expire_password," \
     "and the old password is refused"
