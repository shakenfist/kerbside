#!/bin/bash
# Prove the Rust proxy's tunnelled backend leg end to end, gating the
# direct-qemu functional workflow.
#
# A tunnelled Target tells the proxy to reach qemu's TLS port only through an
# HTTP CONNECT proxy, asking it for an opaque connect host (on Proxmox, a
# pseudo-hostname with a signed ticket in it). Here that proxy is
# connect-proxy.py, which, like Proxmox's spiceproxy, accepts a CONNECT only
# when its request line and Host: header both name the expected connect host
# and port, relays it to qemu's TLS listener, and answers anything else 401.
# It records counts of tunnels opened and requests refused in a status file.
#
# Every mode runs on the standalone Rust-proxy harness (verify-rust-proxy.sh)
# with BACKEND_TLS=1, and the mock gRPC server hands out a Target whose
# hypervisor_ip is 192.0.2.1 (TEST-NET-1, which nothing answers), so a
# session that comes up can only have come through the CONNECT proxy. The
# connect host is a fresh random sentinel per mode, shaped like Proxmox's and
# kept in a 0600 file. The modes, each in its own workdir and torn down
# before the next:
#
#   match      -- the correct host_subject pin. The client must get a
#                 session (assert-host-subject match), and the CONNECT proxy
#                 must have opened at least one tunnel for every channel the
#                 proxy relayed, and refused nothing.
#   no-subject -- no host_subject pin, which a tunnel requires. The session
#                 must fail, the mock's audit log must hold a "Hypervisor
#                 connection failed" event naming host_subject
#                 (assert-host-subject none), and the CONNECT proxy must
#                 never have been asked for anything.
#   mismatch   -- a wrong host_subject pin. The session must fail at the TLS
#                 handshake through the tunnel (assert-host-subject
#                 mismatch), so the CONNECT proxy must have opened at least
#                 one tunnel and refused nothing.
#
# Each mode's logs are copied to TUNNEL_ARTIFACTS/<mode> for CI upload, and
# this script's own output, which is what the step log shows, is kept in
# TUNNEL_ARTIFACTS/console.log. On exit every collected artifact is searched
# for each mode's connect host; any file holding one is removed with an
# ERROR, and the run fails.
#
# Ports are verify-rust-proxy.sh's defaults (proxy 5900/5901, qemu SPICE
# 5910 and TLS 5911) plus CONNECT_PROXY_PORT, so this must not run alongside
# another lane; the workflow runs it after the host-subject checks.
#
# Env overrides: TUNNEL_WORKDIR (base workdir, default
# /tmp/kerbside-tunnel-checks), TUNNEL_ARTIFACTS (default
# /tmp/tunnel-artifacts), CONNECT_PROXY_PORT (default 13128), QEMU_TLS_PORT
# (default 5911), RYLL_BIN (default `ryll` resolved via PATH),
# RYLL_READY_TIMEOUT (seconds to wait for ryll's control socket, default 30),
# and anything verify-rust-proxy.sh reads.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${SCRIPT_DIR}/verify-rust-proxy.sh"

BASE_WORKDIR="${TUNNEL_WORKDIR:-/tmp/kerbside-tunnel-checks}"
TUNNEL_ARTIFACTS="${TUNNEL_ARTIFACTS:-/tmp/tunnel-artifacts}"
CONNECT_PROXY_PORT="${CONNECT_PROXY_PORT:-13128}"
RYLL_BIN="${RYLL_BIN:-ryll}"
RYLL_READY_TIMEOUT="${RYLL_READY_TIMEOUT:-30}"

export BACKEND_TLS=1
export QEMU_TLS_PORT="${QEMU_TLS_PORT:-5911}"
export MOCK_HYPERVISOR_IP='192.0.2.1'
export TUNNEL_PROXY_URI="http://127.0.0.1:${CONNECT_PROXY_PORT}"

# Every mode's connect host, for the leak check on exit. Owner-only, and
# outside every directory that is collected.
SENTINELS_FILE="${BASE_WORKDIR}-sentinels"

# Populated per mode by _run_mode; initialised here so `set -u` never trips
# if cleanup fires before the first mode sets them.
MODE=''
WORKDIR=''
RYLL_SOCK=''
RYLL_STDOUT=''
RYLL_STDERR=''
RYLL_PID_FILE=''
CONSOLE_VV=''
CONNECT_PID_FILE=''
CONNECT_STATUS=''
CONNECT_LOG=''
CONSOLE_TEE_PID=''

# ── Teardown ───────────────────────────────────────────────────────────────

_kill_pid_file() {
    local label="$1"
    local pidfile="$2"
    if [ -z "${pidfile}" ] || [ ! -f "${pidfile}" ]; then
        return 0
    fi
    local pid
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        echo "[tunnel-checks] stopping ${label} (pid ${pid})"
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 1
        kill -KILL "${pid}" 2>/dev/null || true
    fi
    rm -f "${pidfile}"
}

# Stop everything the current mode started and collect its logs. Safe to
# call twice.
_mode_down() {
    if [ -z "${MODE}" ]; then
        return 0
    fi
    _kill_pid_file 'ryll' "${RYLL_PID_FILE}"
    _kill_pid_file 'connect-proxy' "${CONNECT_PID_FILE}"
    WORKDIR="${WORKDIR}" "${HARNESS}" down || true

    local dest="${TUNNEL_ARTIFACTS}/${MODE}"
    rm -rf "${dest}"
    mkdir -p "${dest}"
    for f in rust-proxy.log mock-grpc.log sextant-serial.log console.vv \
             ryll-ci.stdout ryll-ci.stderr connect-proxy.status connect-proxy.log; do
        if [ -f "${WORKDIR}/${f}" ]; then
            cp "${WORKDIR}/${f}" "${dest}/" 2>/dev/null || true
        fi
    done
    rm -f "${WORKDIR}/connect-host"
    MODE=''
}

cleanup() {
    local rc=$?
    _mode_down
    if [ -n "${CONSOLE_TEE_PID}" ]; then
        exec 1>&3 2>&4
        wait "${CONSOLE_TEE_PID}" 2>/dev/null || true
    fi
    if [ -s "${SENTINELS_FILE}" ] && [ -d "${TUNNEL_ARTIFACTS}" ]; then
        local leaked
        leaked=$(grep -rlF -f "${SENTINELS_FILE}" "${TUNNEL_ARTIFACTS}" || true)
        if [ -n "${leaked}" ]; then
            while read -r f; do
                echo "ERROR: a tunnel connect host appears in ${f}; removed it" >&2
                rm -f "${f}"
            done <<< "${leaked}"
            rc=1
        else
            echo "[tunnel-checks] no connect host appears in any collected artifact"
        fi
    fi
    rm -f "${SENTINELS_FILE}"
    exit "${rc}"
}
trap cleanup EXIT

# ── The connect host ───────────────────────────────────────────────────────
#
# Shaped like Proxmox's pseudo-hostname (pvespiceproxy:<hex time>:<vmid>:
# <node>:<port>::<signature>), with a random signature. Never printed. The
# signature is also recorded on its own, so a leak that mangles the rest of
# the host is still caught.

_new_connect_host() {
    local file="$1"
    local signature
    signature="$(od -An -N20 -tx1 /dev/urandom | tr -d ' \n')"
    (
        umask 077
        printf 'pvespiceproxy:%08X:100:ci:%d::%s\n' "$(date +%s)" "${QEMU_TLS_PORT}" "${signature}" \
            > "${file}"
        cat "${file}" >> "${SENTINELS_FILE}"
        printf '%s\n' "${signature}" >> "${SENTINELS_FILE}"
    )
}

# ── The CONNECT proxy ──────────────────────────────────────────────────────

_start_connect_proxy() {
    python3 "${SCRIPT_DIR}/connect-proxy.py" \
        --listen-port "${CONNECT_PROXY_PORT}" \
        --port "${QEMU_TLS_PORT}" \
        --expected-host-file "${WORKDIR}/connect-host" \
        --status-file "${CONNECT_STATUS}" \
        > "${CONNECT_LOG}" 2>&1 &
    local pid=$!
    printf '%d' "${pid}" > "${CONNECT_PID_FILE}"

    # The status file is written once the listener is bound.
    local deadline=$(( $(date +%s) + 15 ))
    while [ ! -f "${CONNECT_STATUS}" ]; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "ERROR: connect-proxy.py exited before it was ready" >&2
            cat "${CONNECT_LOG}" >&2 || true
            exit 1
        fi
        if [ "$(date +%s)" -ge "${deadline}" ]; then
            echo "ERROR: connect-proxy.py was not ready within 15s" >&2
            exit 1
        fi
        sleep 0.2
    done
    echo "[tunnel-checks] connect-proxy.py listening on 127.0.0.1:${CONNECT_PROXY_PORT} (pid ${pid})"
}

# A missing or non-numeric count fails the run: compared with -ne or -lt, an
# empty value is an error that `if` would read as a passing check.
_proxy_count() {
    local value
    value="$(awk -F= -v name="$1" '$1 == name {print $2}' "${CONNECT_STATUS}")"
    if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: ${CONNECT_STATUS} has no count for $1" >&2
        exit 1
    fi
    printf '%s' "${value}"
}

# ── Client driver ──────────────────────────────────────────────────────────
#
# As in run-host-subject-checks.sh: launch ryll headless against the mode's
# console.vv, wait for its control socket, and drive it with smoke-client.py.
# Returns non-zero if ryll never comes up or smoke-client fails; callers
# decide whether that is gating.

_drive_client() {
    echo "[tunnel-checks] launching ryll headless against ${CONSOLE_VV}"
    "${RYLL_BIN}" --verbose --headless --file "${CONSOLE_VV}" \
        --control-socket "${RYLL_SOCK}" \
        --enable-paste-as-keystrokes \
        > "${RYLL_STDOUT}" 2> "${RYLL_STDERR}" &
    local ryll_pid=$!
    printf '%d' "${ryll_pid}" > "${RYLL_PID_FILE}"

    local deadline=$(( $(date +%s) + RYLL_READY_TIMEOUT ))
    while [ ! -S "${RYLL_SOCK}" ]; do
        if ! kill -0 "${ryll_pid}" 2>/dev/null; then
            echo "[tunnel-checks] ryll exited before its control socket appeared"
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

    local client_rc=0
    python3 "${SCRIPT_DIR}/smoke-client.py" "${RYLL_SOCK}" || client_rc=$?
    _kill_pid_file 'ryll' "${RYLL_PID_FILE}"
    return "${client_rc}"
}

# ── The CONNECT proxy's counts, per mode ───────────────────────────────────

_assert_counts() {
    local tunnels refused upstream_failed relays
    tunnels="$(_proxy_count tunnels)"
    refused="$(_proxy_count refused)"
    upstream_failed="$(_proxy_count upstream_failed)"
    relays="$(grep -c 'relay starting' "${WORKDIR}/rust-proxy.log" || true)"
    echo "[tunnel-checks] connect-proxy: tunnels=${tunnels} refused=${refused}" \
         "upstream_failed=${upstream_failed}; channels relayed=${relays}"

    if [ "${refused}" -ne 0 ] || [ "${upstream_failed}" -ne 0 ]; then
        echo "ERROR: the CONNECT proxy refused or failed a request in mode ${MODE}" >&2
        exit 1
    fi
    case "${MODE}" in
        match)
            if [ "${relays}" -lt 1 ] || [ "${tunnels}" -lt "${relays}" ]; then
                echo "ERROR: expected at least one tunnel per relayed channel (and at least" \
                     "one channel), got tunnels=${tunnels} channels=${relays}" >&2
                exit 1
            fi
            ;;
        no-subject)
            if [ "${tunnels}" -ne 0 ]; then
                echo "ERROR: a target without a host_subject pin opened ${tunnels} tunnel(s)" >&2
                exit 1
            fi
            ;;
        mismatch)
            if [ "${tunnels}" -lt 1 ] || [ "${relays}" -ne 0 ]; then
                echo "ERROR: expected the TLS handshake to fail inside a tunnel, got" \
                     "tunnels=${tunnels} channels=${relays}" >&2
                exit 1
            fi
            ;;
    esac
}

# ── One full up/drive/assert/down cycle for a single mode ──────────────────

_run_mode() {
    local mode="$1"            # match | no-subject | mismatch
    local subject_expect="$2"  # verify-rust-proxy.sh's HOST_SUBJECT_EXPECT

    MODE="${mode}"
    export WORKDIR="${BASE_WORKDIR}-${mode}"
    export HOST_SUBJECT_EXPECT="${subject_expect}"
    export TUNNEL_CONNECT_HOST_FILE="${WORKDIR}/connect-host"
    RYLL_SOCK="${WORKDIR}/ryll-ci.sock"
    RYLL_STDOUT="${WORKDIR}/ryll-ci.stdout"
    RYLL_STDERR="${WORKDIR}/ryll-ci.stderr"
    RYLL_PID_FILE="${WORKDIR}/ryll.pid"
    CONSOLE_VV="${WORKDIR}/console.vv"
    CONNECT_PID_FILE="${WORKDIR}/connect-proxy.pid"
    CONNECT_STATUS="${WORKDIR}/connect-proxy.status"
    CONNECT_LOG="${WORKDIR}/connect-proxy.log"

    echo "[tunnel-checks] === mode=${mode} (WORKDIR=${WORKDIR}) ==="
    rm -rf "${WORKDIR}"
    mkdir -p "${WORKDIR}"
    _new_connect_host "${TUNNEL_CONNECT_HOST_FILE}"
    _start_connect_proxy
    "${HARNESS}" up

    if [ "${mode}" = 'match' ]; then
        _drive_client
    else
        _drive_client || true
    fi

    "${HARNESS}" assert-host-subject
    _assert_counts
    _mode_down
}

# Keep a copy of everything this run prints, which is what the public step
# log shows, so the leak check on exit covers the log as well as the files.
# cleanup() puts the original stdout and stderr back and waits for tee, so
# the copy is complete before it is searched.
mkdir -p "${TUNNEL_ARTIFACTS}"
exec 3>&1 4>&2
exec > >(tee -a "${TUNNEL_ARTIFACTS}/console.log") 2>&1
CONSOLE_TEE_PID=$!

( umask 077; : > "${SENTINELS_FILE}" )
chmod 600 "${SENTINELS_FILE}"

_run_mode match match
_run_mode no-subject none
_run_mode mismatch mismatch

echo "[tunnel-checks] PASS: match, no-subject and mismatch tunnel outcomes verified"
