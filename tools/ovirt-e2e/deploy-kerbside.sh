#!/bin/bash
# Deploy kerbside on the CI runner, pointed at the lane's oVirt engine.
#
# Runs LOCALLY on the runner -- there is no SSH anywhere in this script.
# Kerbside deliberately does not live on the oVirt node: that node is Rocky 8
# with a Python 3.6 system interpreter, and pyproject.toml sets
# requires-python = ">=3.11". The runner is Debian 12, already carries the
# whole direct-qemu toolchain pattern, and is attached to the 10.0.2.0/24 test
# network, so it reaches the engine at ovirt.local and the hypervisor's SPICE
# ports at 10.0.2.2 directly. Running off-box also exercises the realistic
# front-door topology, where kerbside is on its own host.
#
# The script installs the build prerequisites, creates the kerbside MariaDB
# database, builds a venv containing the PR's kerbside plus the PR's Rust proxy
# wheel, generates proxy TLS material, writes a sources.yaml holding one
# type: ovirt source, starts kerbside by REUSING
# tools/direct-qemu/start-kerbside.sh, writes an env file for the driver, and
# finally waits for the oVirt source to reach a non-errored state.
#
# start-kerbside.sh already hardcodes everything this deployment wants --
# KERBSIDE_SQL_URL='mysql://kerbside:kerbside@127.0.0.1/kerbside',
# KERBSIDE_PUBLIC_FQDN='127.0.0.1', a KERBSIDE_PROXY_HOST_SUBJECT matching
# generate-tls.sh, the CI metrics port and the API socket path -- and it runs
# the alembic migration, writes the auth seed the driver needs, and waits for
# both the REST API and the SPICE proxy listener. That is why we reuse the
# proven script rather than fork a near-identical oVirt variant.
#
# Usage:
#   deploy-kerbside.sh \
#     --engine-url   URL  (e.g. https://ovirt.local/ovirt-engine, no /api) \
#     --username     USER (e.g. admin@internal) \
#     --password     PASS \
#     --kerbside-src DIR  (the kerbside checkout to install) \
#     --proxy-wheel  GLOB (the built kerbside-proxy wheel) \
#     [--source-name ovirt] \
#     [--api-port 13002]
#
# SECURITY: never echoes the engine password, the auth seed, or key material.
# Part of docs/plans/PLAN-two-tier-ci-phase-01-ovirt-kerbside.md.

set -euo pipefail

ENGINE_URL=''
USERNAME=''
PASSWORD=''
KERBSIDE_SRC=''
PROXY_WHEEL=''
SOURCE_NAME='ovirt'
API_PORT='13002'

while [ $# -gt 0 ]; do
    case "$1" in
        --engine-url)   ENGINE_URL="$2";   shift 2 ;;
        --username)     USERNAME="$2";     shift 2 ;;
        --password)     PASSWORD="$2";     shift 2 ;;
        --kerbside-src) KERBSIDE_SRC="$2"; shift 2 ;;
        --proxy-wheel)  PROXY_WHEEL="$2";  shift 2 ;;
        --source-name)  SOURCE_NAME="$2";  shift 2 ;;
        --api-port)     API_PORT="$2";     shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

for name in ENGINE_URL USERNAME PASSWORD KERBSIDE_SRC PROXY_WHEEL; do
    if [ -z "${!name}" ]; then
        echo "ERROR: --${name,,} is required" >&2
        exit 1
    fi
done

# Loopback traffic to kerbside on 127.0.0.1 must bypass the runner's squid,
# which 503s it otherwise.
export no_proxy="${no_proxy:-},127.0.0.1,localhost"

WORKDIR="${WORKDIR:-/tmp/kerbside-ovirt-ci}"
VENV="${WORKDIR}/venv"
TLS_DIR="${WORKDIR}/tls"
SOURCES_PATH="${WORKDIR}/sources.yaml"
LOG_PATH="${WORKDIR}/kerbside.log"
# PID_FILE must sit directly in WORKDIR: start-kerbside.sh derives the auth
# seed path (and the gRPC socket path) from $(dirname "${PID_FILE}").
PID_FILE="${WORKDIR}/kerbside.pid"
SEED_FILE="${WORKDIR}/kerbside-auth-seed.txt"
KERBSIDE_ENV="${WORKDIR}/kerbside.env"

mkdir -p "${WORKDIR}"

# ── Step 1: Install build prerequisites ──────────────────────────────────────
#
# libxml2-dev, libxslt1-dev, libcurl4-openssl-dev and build-essential are here
# for ovirt-engine-sdk-python, which is a C extension.

echo "[ovirt-e2e] Installing build prerequisites"
sudo apt-get update
sudo apt-get install -y \
    mariadb-server build-essential cmake pkg-config libssl-dev \
    default-libmysqlclient-dev libxml2-dev libxslt1-dev \
    libcurl4-openssl-dev python3 python3-pip python3-venv \
    curl openssl

# ── Step 2: Create the kerbside MariaDB database and user ────────────────────

echo "[ovirt-e2e] Creating the kerbside MariaDB database and user"
"${KERBSIDE_SRC}/tools/direct-qemu/setup-mariadb.sh"

# ── Step 3: Create the kerbside venv and install ─────────────────────────────
#
# ovirt-engine-sdk-python is deliberately NOT a kerbside dependency: it is
# commented out in pyproject.toml and kerbside/sources/ovirt.py imports it
# lazily, erroring the source if it is absent. So install it explicitly here.

echo "[ovirt-e2e] Creating venv at ${VENV}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip

echo "[ovirt-e2e] Installing kerbside, proxy wheel, gunicorn, oVirt SDK"
# The proxy wheel puts kerbside-proxy on the venv PATH, so the daemon's
# find_proxy_bin() resolves it exactly as a wheel-installed deployment would.
# shellcheck disable=SC2086
"${VENV}/bin/pip" install --quiet \
    "${KERBSIDE_SRC}" ${PROXY_WHEEL} gunicorn ovirt-engine-sdk-python

# start-kerbside.sh invokes gunicorn, alembic, kerbside and python3 bare, so
# they must resolve from the venv.
export PATH="${VENV}/bin:${PATH}"

# ── Step 4: Generate proxy TLS material ──────────────────────────────────────

echo "[ovirt-e2e] Generating proxy TLS material"
"${KERBSIDE_SRC}/tools/direct-qemu/generate-tls.sh" "${TLS_DIR}"

# ── Step 5: Write sources.yaml (one type: ovirt source) ──────────────────────

echo "[ovirt-e2e] Writing sources.yaml"
"${VENV}/bin/python3" "${KERBSIDE_SRC}/tools/ovirt-e2e/gen-sources.py" \
    --output "${SOURCES_PATH}" \
    --engine-url "${ENGINE_URL}" \
    --username "${USERNAME}" \
    --password "${PASSWORD}" \
    --source-name "${SOURCE_NAME}"

# ── Step 6: Start kerbside (reuse start-kerbside.sh) ─────────────────────────

# Belt and braces: the same value start-kerbside.sh sets, exported early so
# the readiness poll below can import kerbside.db before the daemon writes it.
export KERBSIDE_SQL_URL='mysql://kerbside:kerbside@127.0.0.1/kerbside'

echo "[ovirt-e2e] Starting kerbside via start-kerbside.sh"
"${KERBSIDE_SRC}/tools/direct-qemu/start-kerbside.sh" \
    --sources-path "${SOURCES_PATH}" \
    --tls-dir "${TLS_DIR}" \
    --log-path "${LOG_PATH}" \
    --pid-file "${PID_FILE}" \
    --api-port "${API_PORT}"

# ── Step 7: Write the env file the driver reads ──────────────────────────────
#
# Deliberately does not contain the oVirt password: the driver never needs it,
# and this file ends up in the run's artifacts.

cat > "${KERBSIDE_ENV}" << EOF
KERBSIDE_VENV=${VENV}
KERBSIDE_SRC=${KERBSIDE_SRC}
KERBSIDE_WORKDIR=${WORKDIR}
KERBSIDE_SQL_URL=mysql://kerbside:kerbside@127.0.0.1/kerbside
KERBSIDE_SOURCE_NAME=${SOURCE_NAME}
KERBSIDE_SOURCES_PATH=${SOURCES_PATH}
KERBSIDE_API_PORT=${API_PORT}
KERBSIDE_SEED_FILE=${SEED_FILE}
KERBSIDE_LOG_PATH=${LOG_PATH}
RYLL_BIN=/usr/local/bin/ryll
OVIRT_ENGINE_URL=${ENGINE_URL}
EOF
echo "[ovirt-e2e] Wrote ${KERBSIDE_ENV}"

# ── Step 8: Wait for the ovirt source to become healthy ──────────────────────
#
# The daemon's maintenance loop parses sources.yaml and constructs the
# oVirtSource, which re-fetches the engine CA (verified against the one we
# wrote) and compares it for equality.
#
# main.py creates the source row with errored=False before it constructs the
# source object, so an instantaneous "not errored" check would be meaningless
# on its own. It is not meaningless here: daemon_run() calls _parse_sources()
# synchronously before it launches the Rust proxy, and start-kerbside.sh has
# already waited for the proxy's listener, so the first scrape has completed
# and the flag reflects a real verdict by the time we get here. If it comes
# back errored we keep polling anyway, because the maintenance loop retries
# every 60 seconds and a slow engine can lose the first round.
#
# An errored source is by far the most
# likely failure of this whole lane -- a CA mismatch, an engine URL with an
# /api suffix, a missing oVirt SDK, or bad credentials all land here -- and
# kerbside/sources/ovirt.py logs the specific reason via LOG.warning in every
# one of those cases. So on timeout, dump the daemon log: the answer is in it.
#
# The test CONSOLE is not waited for here; the driver polls for it.

echo "[ovirt-e2e] Waiting for the ovirt source to become non-errored..."
DEADLINE=$(( $(date +%s) + 180 ))
while true; do
    if "${VENV}/bin/python3" - "${SOURCE_NAME}" << 'PYEOF'
import sys

from kerbside import db

source_name = sys.argv[1]
source = db.get_source(source_name)
sys.exit(0 if source and not source.get('errored') else 1)
PYEOF
    then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: the ovirt source ${SOURCE_NAME} did not become healthy within 180s" >&2
        echo "  kerbside daemon log tail:" >&2
        tail -60 "${LOG_PATH}" >&2 || true
        exit 1
    fi
    sleep 3
done

echo "[ovirt-e2e] kerbside deployed; the ovirt source is healthy"
