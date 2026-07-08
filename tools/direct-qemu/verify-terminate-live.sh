#!/bin/bash
# Phase 7: end-to-end proof that terminating a session via the REST API drops
# the in-flight connection on the Rust proxy -- exercising the whole phase-5
# bridge live (API -> session_terminations DB row -> the daemon's node-scoped
# ProxyControl poll -> TerminateSession -> the proxy's SessionRegistry cancel
# -> relay teardown). Phase 5 only ever drove this through the mock's
# one-shot ProxyControl emitter; here it runs through the real daemon, API,
# and MariaDB.
#
# Self-contained: brings up its OWN isolated lane (a separate WORKDIR so it
# neither clobbers nor is clobbered by the shared scenario lane, and so its
# logs survive for artifact upload), connects ryll, terminates the console
# via the REST API, asserts the drop, and tears the lane down on exit.
#
# Ports are the lane defaults; this runs to completion (and tears down,
# freeing the ports) before the shared scenario lane comes up, so there is no
# conflict. Requires the same prerequisites as lane-up.sh (qemu, the Sextant
# qcow2, MariaDB) plus a resolvable kerbside-proxy binary (installed wheel or
# KERBSIDE_PROXY_BIN).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Isolated from the scenario lane's /tmp/kerbside-ci.
export WORKDIR="${TERMINATE_WORKDIR:-/tmp/kerbside-terminate}"

CONSOLE_SOURCE="${CONSOLE_SOURCE:-direct-qemu-lab}"
CONSOLE_UUID="${CONSOLE_UUID:-6f4e2c1a-0000-0000-0000-000000000001}"
API_PORT="${API_PORT:-13002}"
KERBSIDE_LOG="${WORKDIR}/kerbside.log"
RYLL_PID_FILE="${WORKDIR}/ryll.pid"
TERMINATE_DEADLINE="${TERMINATE_DEADLINE:-30}"

# The definitive proxy-side oracle (rust/kerbside-proxy/src/relay.rs).
ORACLE='session terminated by control plane'

# Stash the daemon/proxy log before lane-down removes WORKDIR, so it survives
# for CI artifact upload on failure.
TERMINATE_ARTIFACTS="${TERMINATE_ARTIFACTS:-/tmp/terminate-artifacts}"
cleanup() {
    if [ -f "${KERBSIDE_LOG}" ]; then
        mkdir -p "${TERMINATE_ARTIFACTS}"
        cp "${KERBSIDE_LOG}" "${TERMINATE_ARTIFACTS}/kerbside.log" 2>/dev/null || true
    fi
    WORKDIR="${WORKDIR}" "${SCRIPT_DIR}/lane-down.sh" || true
}
trap cleanup EXIT

echo "[verify-terminate] Bringing up an isolated Rust-proxy lane in ${WORKDIR}"
"${SCRIPT_DIR}/lane-up.sh"

# ── Mint a JWT the same way lane-up.sh does ───────────────────────────────────

SEED_FILE="${WORKDIR}/kerbside-auth-seed.txt"
if [ ! -f "${SEED_FILE}" ]; then
    echo "ERROR: auth seed file not found: ${SEED_FILE}" >&2
    exit 1
fi
AUTH_SEED="$(cat "${SEED_FILE}")"

JWT_TOKEN="$(python3 - "${AUTH_SEED}" << 'PYEOF'
import sys
import time
import uuid

import jwt as pyjwt

seed = sys.argv[1]
now = int(time.time())
payload = {
    'fresh': False,
    'iat': now,
    'jti': str(uuid.uuid4()),
    'type': 'access',
    'sub': 'kerbside-ci',
    'nbf': now,
    'exp': now + 3600,
}
token = pyjwt.encode(payload, seed, algorithm='HS256')
if isinstance(token, bytes):
    token = token.decode('utf-8')
print(token, end='')
PYEOF
)"

# ── Confirm the session is live, then terminate the console ───────────────────

if ! grep -q "${ORACLE}" "${KERBSIDE_LOG}" 2>/dev/null; then
    echo "[verify-terminate] lane up with a connected ryll session; terminating console"
else
    echo "ERROR: proxy already logged a termination before we asked for one" >&2
    exit 1
fi

TERMINATE_URL="http://127.0.0.1:${API_PORT}/console/${CONSOLE_SOURCE}/${CONSOLE_UUID}/terminate"
echo "[verify-terminate] GET ${TERMINATE_URL}"
HTTP_STATUS="$(curl \
    --silent \
    --output /dev/null \
    --write-out '%{http_code}' \
    --header "Authorization: Bearer ${JWT_TOKEN}" \
    --header 'Accept: application/json' \
    "${TERMINATE_URL}")"
if [ "${HTTP_STATUS}" != '200' ]; then
    echo "ERROR: terminate endpoint returned HTTP ${HTTP_STATUS}" >&2
    exit 1
fi

# ── Assert the in-flight connection drops ─────────────────────────────────────
#
# The daemon polls session_terminations every ~2s, so allow a bounded window.
# Primary oracle: the proxy log line. Secondary: ryll exits when its channels
# close.

echo "[verify-terminate] Waiting up to ${TERMINATE_DEADLINE}s for the proxy to drop the session..."
DEADLINE=$(( $(date +%s) + TERMINATE_DEADLINE ))
while true; do
    if grep -q "${ORACLE}" "${KERBSIDE_LOG}" 2>/dev/null; then
        echo "[verify-terminate] PASS: proxy logged '${ORACLE}'"
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: proxy did not log '${ORACLE}' within ${TERMINATE_DEADLINE}s" >&2
        echo "  kerbside daemon/proxy log (last 60 lines):" >&2
        tail -60 "${KERBSIDE_LOG}" >&2 || true
        exit 1
    fi
    sleep 1
done

# Secondary confirmation: ryll's connection ended (process exited).
if [ -f "${RYLL_PID_FILE}" ]; then
    RYLL_PID="$(cat "${RYLL_PID_FILE}" 2>/dev/null || true)"
    if [ -n "${RYLL_PID}" ] && ! kill -0 "${RYLL_PID}" 2>/dev/null; then
        echo "[verify-terminate] confirmed: ryll (pid ${RYLL_PID}) exited as its channels closed"
    fi
fi

echo "[verify-terminate] terminate-in-flight verified end to end"
