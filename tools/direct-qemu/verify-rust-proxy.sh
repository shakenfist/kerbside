#!/bin/bash
# Verify the built kerbside-proxy Rust binary end to end, standalone --
# WITHOUT MariaDB and WITHOUT the kerbside daemon/REST API.
#
# Stands up: a real qemu SPICE server (start-qemu.sh), a mock
# KerbsideProxy gRPC service with canned responses (mock-grpc-server.py),
# and the built kerbside-proxy binary (start-rust-proxy.sh), all wired
# together with fresh TLS material (generate-tls.sh). It then writes a
# console.vv pointed at the proxy for a SPICE client to connect through,
# and verifies the path via the proxy's /metrics endpoint.
#
# Full usage documentation (including the firewall warn-only capture and
# the session-termination check): docs/direct-qemu-harness.md.
#
# This is the standalone sibling of lane-up.sh: lane-up.sh exercises the
# proxy behind the full kerbside daemon + MariaDB; this script
# exercises the Rust proxy in isolation, per
# docs/plans/PLAN-rust-proxy-phase-03-proxy-skeleton.md step 3h. The full
# ryll-based direct-qemu CI integration against the Rust proxy is phase 7
# (see docs/proxy-architecture.md).
#
# ── The client step is deliberately pluggable ─────────────────────────────
#
# Driving a real SPICE client headlessly is the hard part, and is left to
# the caller of this script (this script only brings the path up and
# writes console.vv; it does not connect a client itself). Two options:
#
#   (a) GUI, manual: run `remote-viewer "${RYLL_VV}"` (see below for the
#       exact path) and watch it connect. This is the simplest way for an
#       operator to eyeball the connection.
#
#   (b) headless, scripted: launch ryll the way lane-up.sh does --
#         ryll --verbose --headless --file "${RYLL_VV}" \
#             --control-socket "${RYLL_SOCK}" \
#             --enable-paste-as-keystrokes \
#             > "${RYLL_STDOUT}" 2> "${RYLL_STDERR}" &
#       then drive it with tools/direct-qemu/smoke-client.py "${RYLL_SOCK}"
#       once the control socket appears -- exactly as lane-up.sh does for
#       the Python-proxy lane. This requires ryll to be installed/built
#       (see the ryll repo's own build instructions); it is not assumed
#       to be available in every environment this script runs in.
#
# Either way, after the client connects, run `verify-rust-proxy.sh assert`
# (see below) to confirm the proxy actually authorized and relayed traffic
# -- this is what makes the check pass/fail without a GUI or a full
# protocol-level client.
#
# Usage: verify-rust-proxy.sh [up|down|assert|assert-firewall|assert-host-subject]
#   up     (default) -- bring up qemu + mock gRPC server + rust proxy,
#          write console.vv, and print the metrics URL to poll. With
#          BACKEND_TLS=1, qemu additionally opens a SPICE TLS listener
#          (tls-channel=default, so the plaintext port answers
#          need_secured and the proxy's backend leg must retry on the
#          TLS port), and the mock's Target carries the CA plus a
#          host_subject pin: the qemu server cert's real subject when
#          HOST_SUBJECT_EXPECT=match (default), or a deliberately wrong
#          subject when HOST_SUBJECT_EXPECT=mismatch.
#   assert -- poll the proxy's /metrics (GET http://127.0.0.1:<prometheus
#          port>/metrics) and assert kerbside_proxy_authorized_total >= 1
#          and kerbside_proxy_bytes_relayed_total > 0 for BOTH the
#          client_to_server and server_to_client directions, within
#          ASSERT_TIMEOUT seconds (default 30). Exits 0 on success, 1 on
#          assertion failure/timeout, 2 if the endpoint is unreachable.
#          Run this after driving a client through the proxy (step "up"
#          only brings the path up; it does not connect a client).
#   assert-firewall -- poll /metrics, report the
#          kerbside_proxy_firewall_verdicts_total series split into
#          action=enforced vs action=observed, and pass/fail per
#          FIREWALL_EXPECT (default "clean"):
#            clean -- a legitimate warn-only capture session: require a real
#                     session (authorized>=1, bytes both directions) and then
#                     assert ZERO enforced AND ZERO observed verdicts. Any
#                     observed verdict means the allowlist/caps are wrong.
#            deny  -- a deny-mode run: require kerbside_proxy_denied_total >= 1
#                     (the proxy exercised its PermissionDenied path). Bytes
#                     are not required. Verdicts are still reported.
#          Same exit codes as `assert`.
#   assert-host-subject -- judge a BACKEND_TLS=1 lane per HOST_SUBJECT_EXPECT:
#            match    -- same bar as `assert` (authorized >= 1, bytes both
#                        directions -- through the TLS backend), PLUS the mock
#                        gRPC log must NOT contain a "Hypervisor connection
#                        failed" audit event.
#            mismatch -- require authorized >= 1 (authorization precedes the
#                        backend connect), ZERO bytes relayed in either
#                        direction, a mock-logged audit event matching
#                        "Hypervisor connection failed" +
#                        "NotValidForName" (what the rustls error renders
#                        as in the audit message), AND the proxy log
#                        naming "pinned host_subject" -- together proving
#                        the backend was refused specifically because its
#                        certificate subject did not match the pin. Run
#                        after driving a client (the client's connection
#                        is what triggers the backend attempt; the client
#                        itself fails to get a session, which is the
#                        point).
#          Same exit codes as `assert`.
#   down   -- tear everything down by pidfile (best-effort, never errors).
#
# Env overrides (all optional; see the "Lane parameters" section below for
# defaults): WORKDIR, SPICE_PORT, SPICE_TICKET, PROXY_SECURE_PORT,
# PROXY_INSECURE_PORT, PROXY_PROMETHEUS_PORT, PROXY_NODE_NAME,
# PROXY_HOST_SUBJECT, CONSOLE_SOURCE, CONSOLE_UUID, SESSION_ID,
# RUST_PROXY_BINARY, and the firewall/denial knobs threaded into the mock:
# FIREWALL_MODE (enforce|warn, default enforce), PERMITTED_CHANNELS (CSV of
# channel names, empty = permit all), DENY_TOKEN (CSV of plaintext tokens to
# deny), DENY_ALL (non-empty to deny every token), FIREWALL_EXPECT
# (clean|deny, for assert-firewall), plus the backend-TLS knobs: BACKEND_TLS
# (1 to enable the qemu TLS listener + host_subject pinning), QEMU_TLS_PORT,
# BACKEND_HOST_SUBJECT (the pin sent when HOST_SUBJECT_EXPECT=match),
# MISMATCH_HOST_SUBJECT (the pin sent when HOST_SUBJECT_EXPECT=mismatch),
# HOST_SUBJECT_EXPECT (match|mismatch, for up and assert-host-subject).
#
# Part of docs/plans/PLAN-rust-proxy-phase-03-proxy-skeleton.md step 3h and
# docs/plans/PLAN-rust-proxy-phase-04-firewall.md step 4f.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ACTION="${1:-up}"

# ── Lane parameters (override via env) ────────────────────────────────────────

WORKDIR="${WORKDIR:-/tmp/kerbside-rust-proxy-verify}"
TLS_DIR="${TLS_DIR:-${WORKDIR}/tls}"

# The qemu SPICE server (the backend leg the proxy connects to).
SPICE_PORT="${SPICE_PORT:-5910}"
SPICE_TICKET="${SPICE_TICKET:-rust-proxy-verify-ticket}"
QEMU_PID_FILE="${QEMU_PID_FILE:-${WORKDIR}/qemu.pid}"
QEMU_SERIAL_LOG="${QEMU_SERIAL_LOG:-${WORKDIR}/sextant-serial.log}"

# Backend TLS + host_subject pinning (phase-2 of PLAN-host-subject).
# BACKEND_TLS=1 opens a SPICE TLS listener on qemu (tls-channel=default, so
# the plaintext port answers need_secured) using generate-tls.sh's qemu-x509/
# material, and the mock's Target carries the CA plus a host_subject pin.
# BACKEND_HOST_SUBJECT must equal the subject minted for qemu-x509/
# server-cert.pem by generate-tls.sh; MISMATCH_HOST_SUBJECT is any
# well-formed subject that does NOT match it.
BACKEND_TLS="${BACKEND_TLS:-0}"
QEMU_TLS_PORT="${QEMU_TLS_PORT:-5911}"
BACKEND_HOST_SUBJECT="${BACKEND_HOST_SUBJECT:-C=US,O=Kerbside CI,CN=qemu-hv}"
MISMATCH_HOST_SUBJECT="${MISMATCH_HOST_SUBJECT:-CN=not-the-hypervisor}"
HOST_SUBJECT_EXPECT="${HOST_SUBJECT_EXPECT:-match}"
if [ "${HOST_SUBJECT_EXPECT}" != 'match' ] && [ "${HOST_SUBJECT_EXPECT}" != 'mismatch' ]; then
    echo "ERROR: HOST_SUBJECT_EXPECT must be 'match' or 'mismatch', got '${HOST_SUBJECT_EXPECT}'" >&2
    exit 1
fi

# The mock KerbsideProxy gRPC control-plane service.
#
# The socket path must stay under the AF_UNIX SUN_LEN limit (~108 bytes on
# Linux). A deep WORKDIR (e.g. under a long temp/scratch path) will blow past
# it, and both the mock's bind and the proxy's connect then fail with
# "path must be shorter than SUN_LEN". So default the socket to a short path
# under XDG_RUNTIME_DIR (or /tmp), NOT under WORKDIR, and hard-fail early with
# a clear message if an override is too long.
GRPC_SOCKET="${GRPC_SOCKET:-${XDG_RUNTIME_DIR:-/tmp}/kerbside-verify-grpc.sock}"
if [ "${#GRPC_SOCKET}" -ge 108 ]; then
    echo "ERROR: GRPC_SOCKET path is ${#GRPC_SOCKET} bytes; the AF_UNIX limit" \
         "is ~108. Choose a shorter path (e.g. under /tmp): ${GRPC_SOCKET}" >&2
    exit 2
fi
GRPC_PID_FILE="${GRPC_PID_FILE:-${WORKDIR}/mock-grpc.pid}"
GRPC_LOG="${GRPC_LOG:-${WORKDIR}/mock-grpc.log}"
CONSOLE_SOURCE="${CONSOLE_SOURCE:-rust-proxy-verify}"
CONSOLE_UUID="${CONSOLE_UUID:-6f4e2c1a-0000-0000-0000-0000000000f3}"
SESSION_ID="${SESSION_ID:-rust-proxy-verify-session}"
# The Python interpreter used to run mock-grpc-server.py. Must have grpcio
# (matching kerbside's pinned version) installed, and the kerbside package
# importable -- either `pip install -e .` from ${REPO_ROOT} into a venv, or
# PYTHONPATH="${REPO_ROOT}" if grpcio/protobuf are otherwise available.
# This script does NOT create that venv for you.
MOCK_GRPC_PYTHON="${MOCK_GRPC_PYTHON:-python3}"

# Firewall / denial behaviour, threaded into mock-grpc-server.py (phase 4,
# step 4f). Defaults reproduce the phase-3 behaviour: enforce mode, permit
# all channels, deny nothing.
#   FIREWALL_MODE      -- enforce | warn. "warn" runs the safe capture session
#                         (blocking verdicts downgraded to forward+log,
#                         action=observed) so a full legitimate session can be
#                         observed without breaking it.
#   PERMITTED_CHANNELS -- CSV of channel names (main,display,...); empty means
#                         permit all.
#   DENY_TOKEN         -- CSV of decrypted plaintext tokens to deny.
#   DENY_ALL           -- non-empty to deny every AuthorizeConnection.
FIREWALL_MODE="${FIREWALL_MODE:-enforce}"
PERMITTED_CHANNELS="${PERMITTED_CHANNELS:-}"
DENY_TOKEN="${DENY_TOKEN:-}"
DENY_ALL="${DENY_ALL:-}"

# The Rust proxy under test.
PROXY_SECURE_PORT="${PROXY_SECURE_PORT:-5900}"
PROXY_INSECURE_PORT="${PROXY_INSECURE_PORT:-5901}"
PROXY_PROMETHEUS_PORT="${PROXY_PROMETHEUS_PORT:-13030}"
PROXY_NODE_NAME="${PROXY_NODE_NAME:-kerbside-proxy-verify}"
PROXY_HOST_SUBJECT="${PROXY_HOST_SUBJECT:-C=US,O=Kerbside CI,CN=kerbside-ci}"
PROXY_PID_FILE="${PROXY_PID_FILE:-${WORKDIR}/rust-proxy.pid}"
PROXY_LOG="${PROXY_LOG:-${WORKDIR}/rust-proxy.log}"
# Optional: pass a specific binary (release or debug) instead of letting
# start-rust-proxy.sh auto-detect release-then-debug under
# rust/kerbside-proxy/target/.
RUST_PROXY_BINARY="${RUST_PROXY_BINARY:-}"

CONSOLE_VV="${CONSOLE_VV:-${WORKDIR}/console.vv}"
METRICS_URL="http://127.0.0.1:${PROXY_PROMETHEUS_PORT}/metrics"

QCOW2="${REPO_ROOT}/tests/fixtures/uncalibrated-sextant.qcow2"

# ── Teardown ───────────────────────────────────────────────────────────────────

_kill_pid_file() {
    local label="$1"
    local pidfile="$2"

    if [ ! -f "${pidfile}" ]; then
        return 0
    fi

    local pid
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [ -z "${pid}" ]; then
        return 0
    fi

    if kill -0 "${pid}" 2>/dev/null; then
        echo "[verify-rust-proxy] sending SIGTERM to ${label} (pid ${pid})"
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 2
        if kill -0 "${pid}" 2>/dev/null; then
            echo "[verify-rust-proxy] sending SIGKILL to ${label} (pid ${pid})"
            kill -KILL "${pid}" 2>/dev/null || true
        fi
    else
        echo "[verify-rust-proxy] ${label} (pid ${pid}) already gone"
    fi
}

_down() {
    # Reverse startup order: proxy, then the mock control service, then qemu.
    _kill_pid_file 'rust-proxy' "${PROXY_PID_FILE}"
    _kill_pid_file 'mock-grpc-server' "${GRPC_PID_FILE}"
    _kill_pid_file 'qemu' "${QEMU_PID_FILE}"
    echo "[verify-rust-proxy] down"
}

if [ "${ACTION}" = 'down' ]; then
    _down
    exit 0
fi

# ── Metrics-based assertion ───────────────────────────────────────────────────
#
# Parses Prometheus text exposition with grep/awk (no extra Python/jq
# dependency): an unlabeled counter is a line "name value"; a labelled
# series is "name{label=\"value\",...} value". A metric that has never
# been touched may be entirely absent from the output (the `prometheus`
# crate's IntCounterVec only emits a child series once with_label_values
# has been called for that label combination) -- that is treated the same
# as 0, not an error, so the loop just keeps polling until the deadline.

_metric_value() {
    # $1 = metrics body, $2 = metric name, $3 = optional label grep pattern
    local body="$1"
    local name="$2"
    local label_pattern="${3:-}"
    local line
    if [ -n "${label_pattern}" ]; then
        line="$(printf '%s\n' "${body}" | grep -E "^${name}\{" | grep -F "${label_pattern}" | head -1)"
    else
        line="$(printf '%s\n' "${body}" | grep -E "^${name} " | head -1)"
    fi
    if [ -z "${line}" ]; then
        echo '0'
    else
        echo "${line}" | awk '{print $NF}'
    fi
}

# Sum the kerbside_proxy_firewall_verdicts_total children whose action label
# matches $2 ("enforced" or "observed"). A totally-absent series sums to 0.
_verdict_sum() {
    local body="$1"
    local action="$2"
    # The grep stages `|| true` so that ZERO matching series (the clean-session
    # case, where firewall_verdicts_total is entirely absent) yields 0 rather
    # than a failed pipeline that would abort the caller under `set -o pipefail`.
    printf '%s\n' "${body}" \
        | { grep -E '^kerbside_proxy_firewall_verdicts_total\{' || true; } \
        | { grep -F "action=\"${action}\"" || true; } \
        | awk '{sum += $NF} END {print sum + 0}'
}

# Print every firewall_verdicts_total child (or a note if none), one per line.
_report_verdicts() {
    local body="$1"
    local lines
    lines="$(printf '%s\n' "${body}" | grep -E '^kerbside_proxy_firewall_verdicts_total\{' || true)"
    if [ -z "${lines}" ]; then
        echo "[verify-rust-proxy]   (no firewall_verdicts_total series present -- zero verdicts)"
    else
        printf '%s\n' "${lines}" | while IFS= read -r verdict_line; do
            echo "[verify-rust-proxy]   ${verdict_line}"
        done
    fi
}

if [ "${ACTION}" = 'assert-firewall' ]; then
    FIREWALL_EXPECT="${FIREWALL_EXPECT:-clean}"
    ASSERT_TIMEOUT="${ASSERT_TIMEOUT:-30}"
    if [ "${FIREWALL_EXPECT}" != 'clean' ] && [ "${FIREWALL_EXPECT}" != 'deny' ]; then
        echo "ERROR: FIREWALL_EXPECT must be 'clean' or 'deny', got '${FIREWALL_EXPECT}'" >&2
        exit 1
    fi
    echo "[verify-rust-proxy] asserting firewall (expect=${FIREWALL_EXPECT}) via ${METRICS_URL}" \
         "(timeout ${ASSERT_TIMEOUT}s)"

    DEADLINE=$(( $(date +%s) + ASSERT_TIMEOUT ))
    LAST_BODY=''
    while true; do
        if ! LAST_BODY="$(curl --silent --fail --max-time 5 "${METRICS_URL}")"; then
            if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
                echo "ERROR: could not reach ${METRICS_URL} within ${ASSERT_TIMEOUT}s" >&2
                exit 2
            fi
            sleep 1
            continue
        fi

        AUTHORIZED="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_authorized_total')"
        DENIED="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_denied_total')"
        C2S="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_bytes_relayed_total' 'direction="client_to_server"')"
        S2C="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_bytes_relayed_total' 'direction="server_to_client"')"
        ENFORCED="$(_verdict_sum "${LAST_BODY}" 'enforced')"
        OBSERVED="$(_verdict_sum "${LAST_BODY}" 'observed')"

        echo "[verify-rust-proxy] authorized=${AUTHORIZED} denied=${DENIED}" \
             "bytes{c2s}=${C2S} bytes{s2c}=${S2C} verdicts{enforced}=${ENFORCED}" \
             "verdicts{observed}=${OBSERVED}"

        if [ "${FIREWALL_EXPECT}" = 'deny' ]; then
            if [ "${DENIED}" -ge 1 ] 2>/dev/null; then
                echo "[verify-rust-proxy] verdict series:"
                _report_verdicts "${LAST_BODY}"
                echo "[verify-rust-proxy] PASS: denied_total >= 1 (proxy exercised PermissionDenied)"
                exit 0
            fi
        else
            # clean: require a real session to have happened, then demand zero
            # enforced AND zero observed verdicts.
            if [ "${AUTHORIZED}" -ge 1 ] 2>/dev/null && [ "${C2S}" -gt 0 ] 2>/dev/null \
                    && [ "${S2C}" -gt 0 ] 2>/dev/null; then
                echo "[verify-rust-proxy] verdict series:"
                _report_verdicts "${LAST_BODY}"
                if [ "${ENFORCED}" -eq 0 ] 2>/dev/null && [ "${OBSERVED}" -eq 0 ] 2>/dev/null; then
                    echo "[verify-rust-proxy] PASS: full session relayed with ZERO firewall" \
                         "verdicts (allowlist + caps cover all observed traffic)"
                    exit 0
                fi
                echo "ERROR: firewall tripped on legitimate traffic --" \
                     "enforced=${ENFORCED} observed=${OBSERVED} (expected 0/0)" >&2
                echo "  the offending (channel,direction,rule) tell you which table/cap to fix:" >&2
                _report_verdicts "${LAST_BODY}" >&2
                exit 1
            fi
        fi

        if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
            if [ "${FIREWALL_EXPECT}" = 'deny' ]; then
                echo "ERROR: denied_total never reached 1 within ${ASSERT_TIMEOUT}s" \
                     "(last denied=${DENIED})" >&2
            else
                echo "ERROR: no complete session observed within ${ASSERT_TIMEOUT}s" \
                     "(authorized=${AUTHORIZED} c2s=${C2S} s2c=${S2C}); cannot judge a" \
                     "clean firewall run without traffic" >&2
            fi
            echo "  full firewall metrics:" >&2
            printf '%s\n' "${LAST_BODY}" | grep '^kerbside_proxy_' >&2 || true
            echo "  rust-proxy log (last 60 lines):" >&2
            tail -60 "${PROXY_LOG}" >&2 || true
            exit 1
        fi
        sleep 1
    done
fi

if [ "${ACTION}" = 'assert' ]; then
    ASSERT_TIMEOUT="${ASSERT_TIMEOUT:-30}"
    echo "[verify-rust-proxy] asserting relay activity via ${METRICS_URL} (timeout ${ASSERT_TIMEOUT}s)"

    DEADLINE=$(( $(date +%s) + ASSERT_TIMEOUT ))
    LAST_BODY=''
    while true; do
        if ! LAST_BODY="$(curl --silent --fail --max-time 5 "${METRICS_URL}")"; then
            if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
                echo "ERROR: could not reach ${METRICS_URL} within ${ASSERT_TIMEOUT}s" >&2
                exit 2
            fi
            sleep 1
            continue
        fi

        AUTHORIZED="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_authorized_total')"
        C2S="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_bytes_relayed_total' 'direction="client_to_server"')"
        S2C="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_bytes_relayed_total' 'direction="server_to_client"')"

        echo "[verify-rust-proxy] authorized_total=${AUTHORIZED} bytes_relayed{client_to_server}=${C2S}" \
             "bytes_relayed{server_to_client}=${S2C}"

        if [ "${AUTHORIZED}" -ge 1 ] 2>/dev/null && [ "${C2S}" -gt 0 ] 2>/dev/null && [ "${S2C}" -gt 0 ] 2>/dev/null; then
            echo "[verify-rust-proxy] PASS: authorized >= 1 and bytes relayed in both directions"
            exit 0
        fi

        if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
            echo "ERROR: assertion not satisfied within ${ASSERT_TIMEOUT}s" >&2
            echo "  last authorized_total=${AUTHORIZED} client_to_server=${C2S} server_to_client=${S2C}" >&2
            echo "  full metrics body:" >&2
            printf '%s\n' "${LAST_BODY}" | grep '^kerbside_proxy_' >&2 || true
            echo "  rust-proxy log (last 60 lines):" >&2
            tail -60 "${PROXY_LOG}" >&2 || true
            exit 1
        fi
        sleep 1
    done
fi

if [ "${ACTION}" = 'assert-host-subject' ]; then
    ASSERT_TIMEOUT="${ASSERT_TIMEOUT:-30}"
    echo "[verify-rust-proxy] asserting host_subject outcome (expect=${HOST_SUBJECT_EXPECT})" \
         "via ${METRICS_URL} + ${GRPC_LOG} (timeout ${ASSERT_TIMEOUT}s)"

    # Two logs together prove WHY the backend was refused. The audit event
    # ("Hypervisor connection failed: invalid peer certificate:
    # NotValidForName", via the mock's RecordAuditEvent) proves the refusal
    # surfaced to the control plane -- but rustls's error rendering does not
    # name host_subject. The proxy's own log carries the ryll verifier's
    # descriptive line ("pinned host_subject <subject>: ... does not match"),
    # pinning the cause to subject verification specifically. Metrics alone
    # cannot distinguish a subject refusal from a dead backend.
    _mock_failed_audit() {
        grep -F 'Hypervisor connection failed' "${GRPC_LOG}" 2>/dev/null || true
    }
    _proxy_subject_refusal() {
        grep -F 'pinned host_subject' "${PROXY_LOG}" 2>/dev/null || true
    }

    DEADLINE=$(( $(date +%s) + ASSERT_TIMEOUT ))
    LAST_BODY=''
    while true; do
        if ! LAST_BODY="$(curl --silent --fail --max-time 5 "${METRICS_URL}")"; then
            if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
                echo "ERROR: could not reach ${METRICS_URL} within ${ASSERT_TIMEOUT}s" >&2
                exit 2
            fi
            sleep 1
            continue
        fi

        AUTHORIZED="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_authorized_total')"
        C2S="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_bytes_relayed_total' 'direction="client_to_server"')"
        S2C="$(_metric_value "${LAST_BODY}" 'kerbside_proxy_bytes_relayed_total' 'direction="server_to_client"')"
        FAILED_AUDIT="$(_mock_failed_audit)"

        echo "[verify-rust-proxy] authorized=${AUTHORIZED} bytes{c2s}=${C2S} bytes{s2c}=${S2C}" \
             "hypervisor_failure_audit=$([ -n "${FAILED_AUDIT}" ] && echo present || echo absent)"

        if [ "${HOST_SUBJECT_EXPECT}" = 'match' ]; then
            if [ -n "${FAILED_AUDIT}" ]; then
                echo "ERROR: backend connect failed under a MATCHING host_subject pin:" >&2
                printf '%s\n' "${FAILED_AUDIT}" | tail -5 >&2
                echo "  rust-proxy log (last 60 lines):" >&2
                tail -60 "${PROXY_LOG}" >&2 || true
                exit 1
            fi
            if [ "${AUTHORIZED}" -ge 1 ] 2>/dev/null && [ "${C2S}" -gt 0 ] 2>/dev/null \
                    && [ "${S2C}" -gt 0 ] 2>/dev/null; then
                echo "[verify-rust-proxy] PASS: session relayed through the TLS backend with a" \
                     "matching host_subject pin and no hypervisor connection failures"
                exit 0
            fi
        else
            # mismatch: authorization succeeds (it precedes the backend
            # connect), the refusal reaches the audit trail as a certificate
            # name error, the proxy log attributes it to the subject pin,
            # and nothing is ever relayed.
            SUBJECT_REFUSAL="$(_proxy_subject_refusal)"
            if [ "${AUTHORIZED}" -ge 1 ] 2>/dev/null && [ -n "${SUBJECT_REFUSAL}" ] \
                    && printf '%s' "${FAILED_AUDIT}" | grep -q 'NotValidForName'; then
                if [ "${C2S}" -eq 0 ] 2>/dev/null && [ "${S2C}" -eq 0 ] 2>/dev/null; then
                    echo "[verify-rust-proxy] refusal audit event:"
                    printf '%s\n' "${FAILED_AUDIT}" | tail -1 | sed 's/^/[verify-rust-proxy]   /'
                    echo "[verify-rust-proxy] proxy subject-verification refusal:"
                    printf '%s\n' "${SUBJECT_REFUSAL}" | tail -1 | sed 's/^/[verify-rust-proxy]   /'
                    echo "[verify-rust-proxy] PASS: mismatched host_subject pin refused the" \
                         "backend (audit event + proxy refusal log, zero bytes relayed)"
                    exit 0
                fi
                echo "ERROR: bytes were relayed despite a host_subject refusal --" \
                     "c2s=${C2S} s2c=${S2C} (expected 0/0)" >&2
                exit 1
            fi
        fi

        if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
            echo "ERROR: host_subject assertion (expect=${HOST_SUBJECT_EXPECT}) not satisfied" \
                 "within ${ASSERT_TIMEOUT}s" >&2
            echo "  last authorized=${AUTHORIZED} c2s=${C2S} s2c=${S2C}" >&2
            echo "  mock gRPC audit lines mentioning hypervisor failure:" >&2
            _mock_failed_audit | tail -5 >&2
            echo "  rust-proxy log (last 60 lines):" >&2
            tail -60 "${PROXY_LOG}" >&2 || true
            exit 1
        fi
        sleep 1
    done
fi

if [ "${ACTION}" != 'up' ]; then
    echo "Usage: $0 [up|down|assert|assert-firewall|assert-host-subject]" >&2
    exit 1
fi

# ── Step 1: workdir + TLS material ───────────────────────────────────────────

echo "[verify-rust-proxy] WORKDIR=${WORKDIR}"
mkdir -p "${WORKDIR}"

"${SCRIPT_DIR}/generate-tls.sh" "${TLS_DIR}"

# ── Step 2: locate OVMF firmware and boot qemu ───────────────────────────────
#
# Mirrors lane-up.sh's OVMF detection exactly (kept independent rather than
# factored out, since lane-up.sh is not a library other scripts source).

if [ -f '/usr/share/OVMF/OVMF_CODE_4M.fd' ] && [ -f '/usr/share/OVMF/OVMF_VARS_4M.fd' ]; then
    OVMF_CODE='/usr/share/OVMF/OVMF_CODE_4M.fd'
    OVMF_VARS='/usr/share/OVMF/OVMF_VARS_4M.fd'
elif [ -f '/usr/share/OVMF/OVMF_CODE.fd' ] && [ -f '/usr/share/OVMF/OVMF_VARS.fd' ]; then
    OVMF_CODE='/usr/share/OVMF/OVMF_CODE.fd'
    OVMF_VARS='/usr/share/OVMF/OVMF_VARS.fd'
elif [ -f '/usr/share/ovmf/OVMF.fd' ]; then
    OVMF_CODE='/usr/share/ovmf/OVMF.fd'
    OVMF_VARS='/usr/share/ovmf/OVMF.fd'
else
    echo "ERROR: OVMF firmware not found; install the ovmf package" >&2
    exit 1
fi
echo "[verify-rust-proxy] OVMF: ${OVMF_CODE}"

if [ ! -f "${QCOW2}" ]; then
    echo "ERROR: qcow2 fixture not found: ${QCOW2}" >&2
    exit 1
fi

QEMU_ARGS=(
    --qcow2 "${QCOW2}"
    --ovmf-code "${OVMF_CODE}"
    --ovmf-vars "${OVMF_VARS}"
    --spice-port "${SPICE_PORT}"
    --ticket "${SPICE_TICKET}"
    --serial-log "${QEMU_SERIAL_LOG}"
    --pid-file "${QEMU_PID_FILE}"
)
if [ "${BACKEND_TLS}" = '1' ]; then
    QEMU_ARGS+=(--tls-port "${QEMU_TLS_PORT}" --x509-dir "${TLS_DIR}/qemu-x509")
fi

"${SCRIPT_DIR}/start-qemu.sh" "${QEMU_ARGS[@]}"

# start-qemu.sh's -daemonize only waits for qemu to fork, not for its SPICE
# server to accept connections; poll it directly so the mock gRPC server's
# canned Target (below) points at a backend that is actually listening
# before the rust proxy is started and a client can reach it.
echo "[verify-rust-proxy] Waiting for qemu SPICE port ${SPICE_PORT}..."
DEADLINE=$(( $(date +%s) + 30 ))
while true; do
    if python3 -c \
            "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', ${SPICE_PORT})); s.close()" \
            2>/dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: qemu SPICE port ${SPICE_PORT} did not come up within 30s" >&2
        tail -40 "${QEMU_SERIAL_LOG}" >&2 || true
        exit 1
    fi
    sleep 0.5
done
echo "[verify-rust-proxy] qemu SPICE server up on port ${SPICE_PORT}"

# ── Step 3: start the mock KerbsideProxy gRPC server ─────────────────────────

echo "[verify-rust-proxy] Starting mock-grpc-server.py (firewall_mode=${FIREWALL_MODE}" \
     "permitted_channels=${PERMITTED_CHANNELS:-<all>} deny_all=${DENY_ALL:-0}" \
     "deny_token=${DENY_TOKEN:+<set>})"
MOCK_ARGS=(
    --socket "${GRPC_SOCKET}"
    --hypervisor-ip '127.0.0.1'
    --insecure-port "${SPICE_PORT}"
    --ticket "${SPICE_TICKET}"
    --source "${CONSOLE_SOURCE}"
    --uuid "${CONSOLE_UUID}"
    --session-id "${SESSION_ID}"
    --firewall-mode "${FIREWALL_MODE}"
    --permitted-channels "${PERMITTED_CHANNELS}"
    --verbose
)
if [ "${BACKEND_TLS}" = '1' ]; then
    # The Target carries the TLS pieces the production servicer would send:
    # the qemu TLS port as secure_port (the proxy's plaintext attempt on
    # insecure_port gets need_secured and retries here), the CA as inline
    # PEM (matching kerbside/rpc/servicer.py, which sends the source's
    # ca_cert column contents), and the host_subject pin -- the server
    # cert's real subject, or a deliberately wrong one under
    # HOST_SUBJECT_EXPECT=mismatch.
    if [ "${HOST_SUBJECT_EXPECT}" = 'mismatch' ]; then
        TARGET_HOST_SUBJECT="${MISMATCH_HOST_SUBJECT}"
    else
        TARGET_HOST_SUBJECT="${BACKEND_HOST_SUBJECT}"
    fi
    echo "[verify-rust-proxy] backend TLS on: secure_port=${QEMU_TLS_PORT}" \
         "host_subject='${TARGET_HOST_SUBJECT}' (expect=${HOST_SUBJECT_EXPECT})"
    MOCK_ARGS+=(
        --secure-port "${QEMU_TLS_PORT}"
        --ca-cert "$(cat "${TLS_DIR}/ca-cert.pem")"
        --host-subject "${TARGET_HOST_SUBJECT}"
    )
else
    MOCK_ARGS+=(--secure-port 0)
fi
if [ -n "${DENY_ALL}" ]; then
    MOCK_ARGS+=(--deny-all)
fi
# DENY_TOKEN is a CSV; the mock seeds tokens from MOCK_GRPC_DENY_TOKEN too, so
# export it rather than splitting here (keeps quoting simple for tokens that
# may contain shell-special characters).
MOCK_GRPC_DENY_TOKEN="${DENY_TOKEN}" \
    "${MOCK_GRPC_PYTHON}" "${SCRIPT_DIR}/mock-grpc-server.py" "${MOCK_ARGS[@]}" \
    >> "${GRPC_LOG}" 2>&1 &
GRPC_PID=$!
printf '%d' "${GRPC_PID}" > "${GRPC_PID_FILE}"
echo "[verify-rust-proxy] mock-grpc-server.py started, pid=${GRPC_PID}"

echo "[verify-rust-proxy] Waiting for gRPC socket at ${GRPC_SOCKET}..."
DEADLINE=$(( $(date +%s) + 15 ))
while true; do
    if [ -S "${GRPC_SOCKET}" ]; then
        break
    fi
    if ! kill -0 "${GRPC_PID}" 2>/dev/null; then
        echo "ERROR: mock-grpc-server.py (pid ${GRPC_PID}) exited before binding its socket" >&2
        tail -60 "${GRPC_LOG}" >&2 || true
        exit 1
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: mock-grpc-server.py socket did not appear within 15s" >&2
        tail -60 "${GRPC_LOG}" >&2 || true
        exit 1
    fi
    sleep 0.5
done
echo "[verify-rust-proxy] mock-grpc-server.py socket ready"

# ── Step 4: start the rust proxy ─────────────────────────────────────────────

START_PROXY_ARGS=(
    --tls-dir "${TLS_DIR}"
    --api-socket "${GRPC_SOCKET}"
    --pid-file "${PROXY_PID_FILE}"
    --log-path "${PROXY_LOG}"
    --secure-port "${PROXY_SECURE_PORT}"
    --insecure-port "${PROXY_INSECURE_PORT}"
    --prometheus-port "${PROXY_PROMETHEUS_PORT}"
    --node-name "${PROXY_NODE_NAME}"
    --host-subject "${PROXY_HOST_SUBJECT}"
    --verbose
)
if [ -n "${RUST_PROXY_BINARY}" ]; then
    START_PROXY_ARGS+=(--binary "${RUST_PROXY_BINARY}")
fi

"${SCRIPT_DIR}/start-rust-proxy.sh" "${START_PROXY_ARGS[@]}"

# ── Step 5: write console.vv pointed at the rust proxy ───────────────────────
#
# Mirrors kerbside/api.py's VIRTVIEWER_TEMPLATE (the "proxy" console.vv
# variant): host/port/tls-port point the client at the PROXY, not at qemu
# directly, so this exercises the full ryll -> kerbside-proxy -> qemu path.
# The password/token value is arbitrary: mock-grpc-server.py's
# AuthorizeConnection authorizes every token unconditionally, so any string
# the proxy can RSA-encrypt and decrypt round-trips fine.
#
# Unlike the production template, delete-this-file is set to 0 here (not
# 1): verification runs are typically repeated by hand against the same
# console.vv, and having virt-viewer/remote-viewer delete it after first
# use would be surprising for that workflow.

CA_CERT_ESCAPED="$(sed ':a;N;$!ba;s/\n/\\n/g' "${TLS_DIR}/ca-cert.pem")"

cat > "${CONSOLE_VV}" << EOF
[virt-viewer]
type=spice
host=127.0.0.1
port=${PROXY_INSECURE_PORT}
tls-port=${PROXY_SECURE_PORT}
password=rust-proxy-verify-any-token-works
delete-this-file=0
fullscreen=0
title=kerbside-proxy verification
toggle-fullscreen=shift+f11
release-cursor=shift+f12
secure-attention=ctrl+alt+end
enable-smartcard=1
enable-usb-autoshare=1
usb-filter=-1,-1,-1,-1,0
tls-ciphers=DEFAULT
ca=${CA_CERT_ESCAPED}
host-subject=${PROXY_HOST_SUBJECT}
EOF

echo "[verify-rust-proxy] console.vv written to ${CONSOLE_VV}"

# ── Step 6: report how to finish the check ───────────────────────────────────

echo
echo "[verify-rust-proxy] up. Next steps:"
echo "  1. Connect a SPICE client through the proxy, e.g.:"
echo "       remote-viewer '${CONSOLE_VV}'"
echo "     or drive ryll headless against it (see the comment block at the"
echo "     top of this script for the exact invocation + smoke-client.py)."
echo "  2. After the client connects, verify relay activity via metrics:"
echo "       curl -s '${METRICS_URL}' | grep kerbside_proxy_"
echo "     Expect kerbside_proxy_authorized_total >= 1 and"
echo "     kerbside_proxy_bytes_relayed_total > 0 for both the"
echo "     client_to_server and server_to_client directions."
echo "       $0 assert"
echo "     For a warn-only capture run (FIREWALL_MODE=warn), also confirm"
echo "     zero firewall verdicts fired on the legitimate session:"
echo "       $0 assert-firewall            # FIREWALL_EXPECT=clean (default)"
echo "     For a deny-mode run (DENY_ALL=1 or DENY_TOKEN=<token>):"
echo "       FIREWALL_EXPECT=deny $0 assert-firewall"
echo "     For a backend-TLS run (BACKEND_TLS=1), judge the host_subject pin:"
echo "       HOST_SUBJECT_EXPECT=${HOST_SUBJECT_EXPECT} $0 assert-host-subject"
echo "  3. Tear down with: $0 down"
echo
echo "[verify-rust-proxy] METRICS_URL=${METRICS_URL}"
echo "[verify-rust-proxy] CONSOLE_VV=${CONSOLE_VV}"
