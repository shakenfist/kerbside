#!/bin/bash
# Bring up the kerbside direct-qemu CI lane.
#
# Orchestrates: TLS generation, QEMU launch, kerbside launch, .vv fetch,
# and ryll launch.  After this script exits 0, the ryll control socket
# at RYLL_SOCK is ready for smoke-client.py.
#
# Expects to find the Sextant qcow2 at tests/fixtures/uncalibrated-sextant.qcow2
# relative to the repo root (detected from the location of this script).
#
# Part of docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md step 5b.

set -euo pipefail

# ── Lane parameters (override via env) ───────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SPICE_PORT="${SPICE_PORT:-5910}"
TICKET="${TICKET:-ci-ticket-vm-1}"
CONSOLE_UUID="${CONSOLE_UUID:-6f4e2c1a-0000-0000-0000-000000000001}"
CONSOLE_SOURCE="${CONSOLE_SOURCE:-direct-qemu-lab}"
HYPERVISOR_NAME="${HYPERVISOR_NAME:-localhost}"
HYPERVISOR_IP="${HYPERVISOR_IP:-127.0.0.1}"
WORKDIR="${WORKDIR:-/tmp/kerbside-ci}"
TLS_DIR="${TLS_DIR:-${WORKDIR}/tls}"
SOURCES_PATH="${SOURCES_PATH:-${WORKDIR}/sources.yaml}"
QEMU_PID_FILE="${QEMU_PID_FILE:-${WORKDIR}/qemu.pid}"
QEMU_SERIAL_LOG="${QEMU_SERIAL_LOG:-${WORKDIR}/sextant-serial.log}"
KERBSIDE_PID_FILE="${KERBSIDE_PID_FILE:-${WORKDIR}/kerbside.pid}"
KERBSIDE_LOG="${KERBSIDE_LOG:-${WORKDIR}/kerbside.log}"
RYLL_SOCK="${RYLL_SOCK:-${WORKDIR}/ryll-ci.sock}"
RYLL_VV="${RYLL_VV:-${WORKDIR}/console.vv}"
RYLL_PID_FILE="${RYLL_PID_FILE:-${WORKDIR}/ryll.pid}"
RYLL_STDERR="${RYLL_STDERR:-${WORKDIR}/ryll-ci.stderr}"
API_PORT="${API_PORT:-13002}"

QCOW2="${REPO_ROOT}/tests/fixtures/uncalibrated-sextant.qcow2"

# ── Step 1: Create workdir and write sources.yaml ─────────────────────────────

echo "[lane-up] WORKDIR=${WORKDIR}"
mkdir -p "${WORKDIR}"

cat > "${SOURCES_PATH}" << EOF
- source: ${CONSOLE_SOURCE}
  type: static
  consoles:
    - uuid: "${CONSOLE_UUID}"
      name: "sextant-vm-1"
      hypervisor: "${HYPERVISOR_NAME}"
      hypervisor_ip: "${HYPERVISOR_IP}"
      insecure_port: ${SPICE_PORT}
      ticket: "${TICKET}"
EOF

echo "[lane-up] sources.yaml written to ${SOURCES_PATH}"

# ── Step 2: Locate OVMF firmware ──────────────────────────────────────────────

# Prefer split code+vars files (Debian ovmf package installs these)
if [ -f '/usr/share/OVMF/OVMF_CODE.fd' ] && [ -f '/usr/share/OVMF/OVMF_VARS.fd' ]; then
    OVMF_CODE='/usr/share/OVMF/OVMF_CODE.fd'
    OVMF_VARS='/usr/share/OVMF/OVMF_VARS.fd'
    echo "[lane-up] OVMF: split files (${OVMF_CODE})"
elif [ -f '/usr/share/ovmf/OVMF.fd' ]; then
    # Some Debian configurations ship a single combined image
    OVMF_CODE='/usr/share/ovmf/OVMF.fd'
    OVMF_VARS='/usr/share/ovmf/OVMF.fd'
    echo "[lane-up] OVMF: single file fallback (${OVMF_CODE})" >&2
else
    echo "ERROR: OVMF firmware not found; install the ovmf package" >&2
    exit 1
fi

# ── Step 3: Generate TLS material ────────────────────────────────────────────

"${SCRIPT_DIR}/generate-tls.sh" "${TLS_DIR}"

# ── Step 4: Boot QEMU ────────────────────────────────────────────────────────

"${SCRIPT_DIR}/start-qemu.sh" \
    --qcow2 "${QCOW2}" \
    --ovmf-code "${OVMF_CODE}" \
    --ovmf-vars "${OVMF_VARS}" \
    --spice-port "${SPICE_PORT}" \
    --ticket "${TICKET}" \
    --serial-log "${QEMU_SERIAL_LOG}" \
    --pid-file "${QEMU_PID_FILE}"

# ── Step 5: Start kerbside ────────────────────────────────────────────────────

"${SCRIPT_DIR}/start-kerbside.sh" \
    --sources-path "${SOURCES_PATH}" \
    --tls-dir "${TLS_DIR}" \
    --log-path "${KERBSIDE_LOG}" \
    --pid-file "${KERBSIDE_PID_FILE}" \
    --api-port "${API_PORT}"

# ── Step 6: Fetch the .vv file from the kerbside REST API ────────────────────
#
# All console endpoints require a JWT Bearer token.  We know the
# AUTH_SECRET_SEED because start-kerbside.sh wrote it to
# ${WORKDIR}/kerbside-auth-seed.txt.  We mint a token directly with
# PyJWT (installed as a dependency of flask-jwt-extended) using the
# same payload shape that flask-jwt-extended's create_access_token
# produces: fresh=false, type=access, sub=<identity>, jti=<uuid>,
# iat=now, exp=now+1h.  The kerbside verify_token decorator only
# calls verify_jwt_in_request which checks the signature and expiry;
# it does not validate any keystone claims.
#
# Endpoint: GET /console/proxy/<source>/<uuid>/console.vv
# The "proxy" variant embeds the CA cert and points ryll at kerbside's
# own SPICE proxy (VDI_INSECURE_PORT / VDI_SECURE_PORT) rather than
# at QEMU's SPICE port directly.  This is the correct endpoint for
# smoke-checking that kerbside sits in the connection path.

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

# flask-jwt-extended depends on PyJWT; import it the same way.
import jwt as pyjwt

seed = sys.argv[1]
now = int(time.time())
payload = {
    'fresh': False,
    'iat': now,
    'jti': str(uuid.uuid4()),
    'type': 'access',
    'sub': ['ci-admin'],
    'nbf': now,
    'exp': now + 3600,
}
token = pyjwt.encode(payload, seed, algorithm='HS256')
# PyJWT >= 2.x returns str; earlier versions returned bytes.
if isinstance(token, bytes):
    token = token.decode('utf-8')
print(token, end='')
PYEOF
)"

VV_URL="http://127.0.0.1:${API_PORT}/console/proxy/${CONSOLE_SOURCE}/${CONSOLE_UUID}/console.vv"
echo "[lane-up] Fetching .vv from ${VV_URL}"

VV_STATUS="$(curl \
    --silent \
    --output "${RYLL_VV}" \
    --write-out '%{http_code}' \
    --header "Authorization: Bearer ${JWT_TOKEN}" \
    "${VV_URL}")"

if [ "${VV_STATUS}" != '200' ]; then
    echo "ERROR: .vv fetch returned HTTP ${VV_STATUS}" >&2
    echo "  response body:" >&2
    cat "${RYLL_VV}" >&2 || true
    echo >&2
    echo "  gunicorn access log:" >&2
    tail -40 "${KERBSIDE_LOG}.gunicorn-access" >&2 || true
    echo "  gunicorn error log:" >&2
    tail -40 "${KERBSIDE_LOG}.gunicorn-error" >&2 || true
    echo "  kerbside daemon log:" >&2
    tail -40 "${KERBSIDE_LOG}" >&2 || true
    exit 1
fi

if [ ! -s "${RYLL_VV}" ]; then
    echo "ERROR: .vv file is empty or was not created: ${RYLL_VV}" >&2
    exit 1
fi

echo "[lane-up] .vv file written to ${RYLL_VV}"

# ── Step 7: Launch ryll ───────────────────────────────────────────────────────

echo "[lane-up] Launching ryll headless"
ryll --headless --file "${RYLL_VV}" --control-socket "${RYLL_SOCK}" \
    2> "${RYLL_STDERR}" &
RYLL_PID=$!
printf '%d' "${RYLL_PID}" > "${RYLL_PID_FILE}"
echo "[lane-up] ryll started, pid=${RYLL_PID}"

# ── Step 8: Poll for the ryll control socket ──────────────────────────────────

echo "[lane-up] Waiting for ryll control socket at ${RYLL_SOCK}..."
DEADLINE=$(( $(date +%s) + 30 ))
while true; do
    if [ -S "${RYLL_SOCK}" ]; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: ryll control socket did not appear within 30s" >&2
        echo "  ryll stderr:" >&2
        tail -20 "${RYLL_STDERR}" >&2 || true
        exit 1
    fi
    sleep 0.5
done

echo "[lane-up] lane up. ryll socket: ${RYLL_SOCK}"
