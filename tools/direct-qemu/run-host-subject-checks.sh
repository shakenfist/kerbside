#!/bin/bash
# Drive both host_subject enforcement outcomes through the standalone
# Rust-proxy harness (verify-rust-proxy.sh), gating the direct-qemu
# functional workflow per phase 2 of PLAN-host-subject.
#
# For each mode (match, then mismatch) this: brings up a BACKEND_TLS=1
# harness lane, launches ryll headless against the harness's console.vv
# (mirroring lane-up.sh's "Launch ryll" step -- the SPICE client must
# actually connect for the proxy's backend leg to attempt the TLS handshake),
# drives it with smoke-client.py (hello/status/screenshot -- the same
# sequence the main lane's "Run smoke client" workflow step uses) so real
# bytes relay both ways, judges the outcome via
# `verify-rust-proxy.sh assert-host-subject`, and tears the lane down before
# moving on.
#
#   match    -- the client is expected to succeed; a client failure here is
#               gating (something is genuinely broken).
#   mismatch -- the client is expected to FAIL to get a session (the
#               backend TLS handshake is refused because of the wrong
#               host_subject pin); that failure is tolerated and non-gating,
#               `assert-host-subject` is what actually judges this mode.
#
# Each mode runs in its OWN workdir (${BASE_WORKDIR}-match /
# ${BASE_WORKDIR}-mismatch) so their proxy/mock/ryll logs never mix, and each
# mode is fully torn down (harness `down`) before the next starts.
#
# Port note: verify-rust-proxy.sh's own lane-parameter defaults
# (proxy 5900/5901, qemu SPICE 5910) are the SAME ports the main direct-qemu
# lane (lane-up.sh / start-kerbside.sh) uses. This script must therefore only
# run after the main lane has been torn down (direct-qemu-functional.yml
# places it after the "Tear down the lane" step) -- otherwise the two lanes'
# bind()s collide.
#
# Env overrides: HOST_SUBJECT_WORKDIR (base workdir, default
# /tmp/kerbside-host-subject-checks), RYLL_BIN (ryll binary, default `ryll`
# resolved via PATH), RYLL_READY_TIMEOUT (seconds to wait for ryll's control
# socket, default 30).
#
# Part of docs/plans/PLAN-host-subject-phase-02-kerbside-adoption.md step 2c.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${SCRIPT_DIR}/verify-rust-proxy.sh"

BASE_WORKDIR="${HOST_SUBJECT_WORKDIR:-/tmp/kerbside-host-subject-checks}"
RYLL_BIN="${RYLL_BIN:-ryll}"
RYLL_READY_TIMEOUT="${RYLL_READY_TIMEOUT:-30}"

export BACKEND_TLS=1

# Populated per-mode by _run_mode; initialised here so `set -u` never trips
# if cleanup fires before the first mode sets them.
WORKDIR=''
RYLL_SOCK=''
RYLL_STDOUT=''
RYLL_STDERR=''
RYLL_PID_FILE=''
CONSOLE_VV=''

# ── Teardown ───────────────────────────────────────────────────────────────

_kill_ryll() {
    if [ -z "${RYLL_PID_FILE}" ] || [ ! -f "${RYLL_PID_FILE}" ]; then
        return 0
    fi
    local pid
    pid="$(cat "${RYLL_PID_FILE}" 2>/dev/null || true)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        echo "[host-subject-checks] stopping ryll (pid ${pid})"
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 1
        kill -KILL "${pid}" 2>/dev/null || true
    fi
    rm -f "${RYLL_PID_FILE}"
}

cleanup() {
    _kill_ryll
    if [ -n "${WORKDIR}" ]; then
        WORKDIR="${WORKDIR}" "${HARNESS}" down || true
    fi
}
trap cleanup EXIT

# ── Client driver ────────────────────────────────────────────────────────────
#
# Launches ryll headless against the current mode's console.vv, waits for its
# control socket, then drives it with smoke-client.py. Returns non-zero if
# ryll never comes up or smoke-client fails -- callers decide whether that is
# gating (match) or tolerated (mismatch, where the client failing to get a
# session is the point).

_drive_client() {
    echo "[host-subject-checks] launching ryll headless against ${CONSOLE_VV}"
    "${RYLL_BIN}" --verbose --headless --file "${CONSOLE_VV}" \
        --control-socket "${RYLL_SOCK}" \
        --enable-paste-as-keystrokes \
        > "${RYLL_STDOUT}" 2> "${RYLL_STDERR}" &
    local ryll_pid=$!
    printf '%d' "${ryll_pid}" > "${RYLL_PID_FILE}"

    local deadline=$(( $(date +%s) + RYLL_READY_TIMEOUT ))
    while [ ! -S "${RYLL_SOCK}" ]; do
        if ! kill -0 "${ryll_pid}" 2>/dev/null; then
            echo "[host-subject-checks] ryll exited before its control socket appeared" \
                 "(expected under a host_subject mismatch)"
            tail -20 "${RYLL_STDERR}" 2>/dev/null || true
            return 1
        fi
        if [ "$(date +%s)" -ge "${deadline}" ]; then
            echo "ERROR: ryll control socket did not appear within ${RYLL_READY_TIMEOUT}s" >&2
            tail -20 "${RYLL_STDERR}" >&2 || true
            return 1
        fi
        sleep 0.5
    done

    python3 "${SCRIPT_DIR}/smoke-client.py" "${RYLL_SOCK}"
    local client_rc=$?
    _kill_ryll
    return "${client_rc}"
}

# ── One full up/drive/assert/down cycle for a single mode ───────────────────

_run_mode() {
    local mode="$1"                # match | mismatch
    local tolerate_client_failure="$2"  # 0 | 1

    export WORKDIR="${BASE_WORKDIR}-${mode}"
    export HOST_SUBJECT_EXPECT="${mode}"
    RYLL_SOCK="${WORKDIR}/ryll-ci.sock"
    RYLL_STDOUT="${WORKDIR}/ryll-ci.stdout"
    RYLL_STDERR="${WORKDIR}/ryll-ci.stderr"
    RYLL_PID_FILE="${WORKDIR}/ryll.pid"
    CONSOLE_VV="${WORKDIR}/console.vv"

    echo "[host-subject-checks] === mode=${mode} (WORKDIR=${WORKDIR}) ==="
    "${HARNESS}" up

    if [ "${tolerate_client_failure}" = '1' ]; then
        _drive_client || true
    else
        _drive_client
    fi

    "${HARNESS}" assert-host-subject
    "${HARNESS}" down
    RYLL_PID_FILE=''
}

_run_mode match 0
_run_mode mismatch 1

echo "[host-subject-checks] PASS: both match and mismatch host_subject outcomes verified"
