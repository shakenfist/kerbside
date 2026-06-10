#!/bin/bash
# Start kerbside (REST API via gunicorn + SPICE proxy via daemon run)
# for the direct-qemu CI lane.
#
# Usage: start-kerbside.sh \
#   --sources-path PATH \
#   --tls-dir PATH \
#   --log-path PATH \
#   --pid-file PATH \
#   [--api-port N]
#
# The REST API is served by gunicorn on API_PORT (default 13002).
# The SPICE proxy is started via "kerbside daemon run" as a separate
# background process.  Both PIDs are captured; the caller should use
# lane-down.sh to clean up.
#
# Database: uses MariaDB to match production (the schema includes
# MySQL-only DDL such as DATETIME(fsp) and CURRENT_TIMESTAMP(6)).
# setup-mariadb.sh must have been run first to create the kerbside
# database and user.  The alembic migration is run in-place from
# KERBSIDE_REPO_ROOT (the repo root that contains alembic.ini).
#
# Part of docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md step 5b.

set -euo pipefail

SOURCES_PATH=''
TLS_DIR=''
LOG_PATH=''
PID_FILE=''
API_PORT='13002'

while [ $# -gt 0 ]; do
    case "$1" in
        --sources-path) SOURCES_PATH="$2"; shift 2 ;;
        --tls-dir)      TLS_DIR="$2";      shift 2 ;;
        --log-path)     LOG_PATH="$2";     shift 2 ;;
        --pid-file)     PID_FILE="$2";     shift 2 ;;
        --api-port)     API_PORT="$2";     shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

for arg in SOURCES_PATH TLS_DIR LOG_PATH PID_FILE; do
    if [ -z "${!arg}" ]; then
        echo "ERROR: --${arg,,} is required (use dashes, not underscores)" >&2
        exit 1
    fi
done

if [ ! -f "${SOURCES_PATH}" ]; then
    echo "ERROR: sources file not found: ${SOURCES_PATH}" >&2
    exit 1
fi

# ── Environment ──────────────────────────────────────────────────────────────

export KERBSIDE_SOURCES_PATH="${SOURCES_PATH}"
export KERBSIDE_CACERT_PATH="${TLS_DIR}/ca-cert.pem"
export KERBSIDE_PROXY_HOST_CERT_PATH="${TLS_DIR}/proxy-cert.pem"
export KERBSIDE_PROXY_HOST_CERT_KEY_PATH="${TLS_DIR}/proxy-key.pem"
export KERBSIDE_LOG_OUTPUT_PATH="${LOG_PATH}"
export KERBSIDE_AUTH_SECRET_SEED
KERBSIDE_AUTH_SECRET_SEED="$(openssl rand -hex 32)"
# MariaDB, set up by setup-mariadb.sh.  Matches the production driver
# (mysqlclient, SQLAlchemy URL prefix mysql://).
export KERBSIDE_SQL_URL='mysql://kerbside:kerbside@127.0.0.1/kerbside'
# Suppress Prometheus metrics port conflicts in CI
export KERBSIDE_PROMETHEUS_METRICS_PORT='13009'
# Proxy .vv configuration: point ryll at localhost on the standard SPICE ports.
# PUBLIC_FQDN is the host ryll will connect to; PUBLIC_SECURE_PORT and
# PUBLIC_INSECURE_PORT default to 5900/5901 and do not need to be overridden.
export KERBSIDE_PUBLIC_FQDN='127.0.0.1'
# PROXY_HOST_SUBJECT must match the CN/subject of proxy-cert.pem as generated
# by generate-tls.sh (subj '/C=US/O=Kerbside CI/CN=kerbside-ci').
export KERBSIDE_PROXY_HOST_SUBJECT='C=US,O=Kerbside CI,CN=kerbside-ci'

# ── Locate repo root (needed for alembic.ini) ────────────────────────────────

# Walk upward from this script to find alembic.ini
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"
while [ "${REPO_ROOT}" != '/' ]; do
    if [ -f "${REPO_ROOT}/alembic.ini" ]; then
        break
    fi
    REPO_ROOT="$(dirname "${REPO_ROOT}")"
done

if [ ! -f "${REPO_ROOT}/alembic.ini" ]; then
    echo "ERROR: could not find alembic.ini from ${SCRIPT_DIR}" >&2
    exit 1
fi

echo "[start-kerbside] Using repo root: ${REPO_ROOT}"

# ── Persist the seed so lane-up.sh can mint a JWT ────────────────────────────

SEED_FILE="$(dirname "${PID_FILE}")/kerbside-auth-seed.txt"
printf '%s' "${KERBSIDE_AUTH_SECRET_SEED}" > "${SEED_FILE}"
chmod 600 "${SEED_FILE}"
echo "[start-kerbside] Auth seed written to ${SEED_FILE}"

# ── Database migration ────────────────────────────────────────────────────────

echo "[start-kerbside] Running alembic upgrade head"
(cd "${REPO_ROOT}" && alembic upgrade head)

# ── Start REST API (gunicorn) ─────────────────────────────────────────────────

GUNICORN_PID_FILE="$(dirname "${PID_FILE}")/kerbside-gunicorn.pid"

gunicorn \
    --bind "0.0.0.0:${API_PORT}" \
    --workers 2 \
    --daemon \
    --pid "${GUNICORN_PID_FILE}" \
    --access-logfile "${LOG_PATH}.gunicorn-access" \
    --error-logfile "${LOG_PATH}.gunicorn-error" \
    'kerbside.api:app'

echo "[start-kerbside] gunicorn started, pid=$(cat "${GUNICORN_PID_FILE}")"

# ── Start SPICE proxy (kerbside daemon run) ───────────────────────────────────

kerbside daemon run >> "${LOG_PATH}" 2>&1 &
DAEMON_PID=$!
printf '%d' "${DAEMON_PID}" > "${PID_FILE}"
echo "[start-kerbside] kerbside daemon run started, pid=${DAEMON_PID}"

# ── Wait for the REST API to accept connections ───────────────────────────────

echo "[start-kerbside] Waiting for API on port ${API_PORT}..."
DEADLINE=$(( $(date +%s) + 30 ))
while true; do
    if curl \
            --max-time 1 \
            --output /dev/null \
            --silent \
            --fail \
            "http://127.0.0.1:${API_PORT}/" \
            -H 'Accept: application/json' 2>/dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: kerbside API did not come up on port ${API_PORT} within 30s" >&2
        echo "  gunicorn error log:" >&2
        tail -40 "${LOG_PATH}.gunicorn-error" >&2 || true
        echo "  gunicorn access log:" >&2
        tail -40 "${LOG_PATH}.gunicorn-access" >&2 || true
        echo "  kerbside daemon log:" >&2
        tail -40 "${LOG_PATH}" >&2 || true
        echo "  one-shot verbose curl to ${API_PORT}/:" >&2
        curl --max-time 3 --verbose \
            "http://127.0.0.1:${API_PORT}/" \
            -H 'Accept: application/json' >&2 || true
        exit 1
    fi
    sleep 0.5
done

echo "[start-kerbside] kerbside REST API up on port ${API_PORT}"

# ── Wait for the SPICE proxy to accept connections ────────────────────────────
#
# The proxy endpoint (/console/proxy/...) generates a .vv that points ryll
# at the SPICE proxy on VDI_SECURE_PORT (default 5900) and
# VDI_INSECURE_PORT (default 5901).  Poll VDI_INSECURE_PORT (5901) so that
# we know the proxy listener is up before lane-up.sh fetches the .vv and
# hands it to ryll.
#
SPICE_PROXY_PORT="${KERBSIDE_VDI_INSECURE_PORT:-5901}"
echo "[start-kerbside] Waiting for SPICE proxy on port ${SPICE_PROXY_PORT}..."
DEADLINE=$(( $(date +%s) + 30 ))
while true; do
    if python3 -c \
            "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', ${SPICE_PROXY_PORT})); s.close()" \
            2>/dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: kerbside SPICE proxy did not come up on port ${SPICE_PROXY_PORT} within 30s" >&2
        echo "  daemon log (last 20 lines):" >&2
        tail -20 "${LOG_PATH}" >&2 || true
        exit 1
    fi
    sleep 0.5
done

echo "[start-kerbside] kerbside SPICE proxy up on port ${SPICE_PROXY_PORT}, daemon pid=$(cat "${PID_FILE}")"
