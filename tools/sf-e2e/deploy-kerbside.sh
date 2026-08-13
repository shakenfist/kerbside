#!/bin/bash
# Deploy kerbside co-located on the Shaken Fist primary node.
#
# Runs ON the SF primary. Creates a kerbside MariaDB db/user in the
# primary's existing MariaDB, builds ryll from source (with the
# digest-decode feature so the visual-digest assertion works), creates a
# venv, installs kerbside + the PR's proxy wheel + shakenfist_client,
# generates proxy TLS, writes sources.yaml with one type: shakenfist
# source, and starts kerbside by REUSING tools/direct-qemu/start-kerbside.sh.
#
# start-kerbside.sh already hardcodes exactly the values this co-located
# case needs -- KERBSIDE_SQL_URL='mysql://kerbside:kerbside@127.0.0.1/kerbside'
# and KERBSIDE_PUBLIC_FQDN='127.0.0.1' -- and passes through any other
# KERBSIDE_* we export. The one thing it does NOT set is the SF token
# audience, so we export KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE before calling
# it. That is why we reuse the proven script rather than fork a
# near-identical primary variant.
#
# Usage:
#   deploy-kerbside.sh \
#     --system-key KEY \
#     --audience   URL   (= SF's KERBSIDE_URL, e.g. http://127.0.0.1:13002) \
#     --kerbside-src DIR (the copied kerbside checkout on the primary) \
#     --proxy-wheel GLOB (the staged kerbside-proxy wheel) \
#     [--sf-url http://localhost:13000] \
#     [--source-name shakenfist] \
#     [--api-port 13002]
#
# SECURITY: never echoes the system key, the auth seed, or key material.

set -euo pipefail

SYSTEM_KEY=''
AUDIENCE=''
KERBSIDE_SRC=''
PROXY_WHEEL=''
SF_URL='http://localhost:13000'
SOURCE_NAME='shakenfist'
API_PORT='13002'

while [ $# -gt 0 ]; do
    case "$1" in
        --system-key)   SYSTEM_KEY="$2";   shift 2 ;;
        --audience)     AUDIENCE="$2";     shift 2 ;;
        --kerbside-src) KERBSIDE_SRC="$2"; shift 2 ;;
        --proxy-wheel)  PROXY_WHEEL="$2";  shift 2 ;;
        --sf-url)       SF_URL="$2";       shift 2 ;;
        --source-name)  SOURCE_NAME="$2";  shift 2 ;;
        --api-port)     API_PORT="$2";     shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

for name in SYSTEM_KEY AUDIENCE KERBSIDE_SRC PROXY_WHEEL; do
    if [ -z "${!name}" ]; then
        echo "ERROR: --${name,,} is required" >&2
        exit 1
    fi
done

# Loopback traffic to kerbside / SF on 127.0.0.1 must bypass any proxy the
# environment configures for apt/pip.
export no_proxy="${no_proxy:-}127.0.0.1,localhost"

SF_E2E_ROOT='/tmp/sf-e2e'
RUN_DIR="${SF_E2E_ROOT}/run"
VENV="${SF_E2E_ROOT}/venv"
TLS_DIR="${RUN_DIR}/tls"
SOURCES_PATH="${RUN_DIR}/sources.yaml"
LOG_PATH="${RUN_DIR}/kerbside.log"
PID_FILE="${RUN_DIR}/kerbside.pid"
SEED_FILE="${RUN_DIR}/kerbside-auth-seed.txt"
KERBSIDE_ENV="${SF_E2E_ROOT}/kerbside.env"

mkdir -p "${RUN_DIR}"

# ── Step 1: Install build prerequisites ──────────────────────────────────────

echo "[sf-e2e] Installing build prerequisites"
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config libssl-dev \
    default-libmysqlclient-dev python3 python3-pip python3-venv \
    curl openssl

# ── Step 2: Create the kerbside MariaDB db/user ──────────────────────────────
#
# The primary's MariaDB (installed by build-smoke-cluster) grants root via
# the unix socket, so `sudo mariadb` needs no password. The kerbside daemon
# connects over TCP as mysql://kerbside:kerbside@127.0.0.1/kerbside, so the
# user is created for any host ('%').

echo "[sf-e2e] Creating the kerbside MariaDB database and user"
sudo mariadb << 'SQL'
CREATE DATABASE IF NOT EXISTS kerbside;
CREATE USER IF NOT EXISTS 'kerbside'@'%' IDENTIFIED BY 'kerbside';
GRANT ALL PRIVILEGES ON kerbside.* TO 'kerbside'@'%';
FLUSH PRIVILEGES;
SQL

# ── Step 3: Build ryll from source with digest-decode ────────────────────────
#
# Mirrors direct-qemu-functional.yml's "Ensure Rust toolchain" + "Build ryll
# from main" steps. The digest-decode feature is what lets the lane drive the
# Sextant on-screen visual digest through ryll's control socket.

if cargo --version > /dev/null 2>&1; then
    echo "[sf-e2e] cargo already available: $(cargo --version)"
else
    echo "[sf-e2e] Installing the Rust toolchain via rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
fi

echo "[sf-e2e] Building ryll from source (--features digest-decode)"
rm -rf /tmp/ryll-src
git clone --depth 1 https://github.com/shakenfist/ryll.git /tmp/ryll-src
(
    cd /tmp/ryll-src
    cargo build --release --no-default-features --features digest-decode -p ryll
    sudo install -m 755 target/release/ryll /usr/local/bin/ryll
)
/usr/local/bin/ryll --version || true

# ── Step 4: Create the kerbside venv and install ─────────────────────────────

echo "[sf-e2e] Creating venv at ${VENV}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip

echo "[sf-e2e] Installing kerbside, proxy wheel, gunicorn, shakenfist_client"
# The proxy wheel puts kerbside-proxy on the venv PATH, so the daemon's
# find_proxy_bin() resolves it exactly as a wheel-installed deployment would.
# shellcheck disable=SC2086
"${VENV}/bin/pip" install --quiet \
    "${KERBSIDE_SRC}" ${PROXY_WHEEL} gunicorn shakenfist_client

export PATH="${VENV}/bin:${PATH}"

# ── Step 5: Generate proxy TLS material ──────────────────────────────────────

echo "[sf-e2e] Generating proxy TLS material"
"${KERBSIDE_SRC}/tools/direct-qemu/generate-tls.sh" "${TLS_DIR}"

# ── Step 6: Write sources.yaml (one type: shakenfist source) ─────────────────

echo "[sf-e2e] Writing sources.yaml"
"${VENV}/bin/python3" "${KERBSIDE_SRC}/tools/sf-e2e/gen-sources.py" \
    --output "${SOURCES_PATH}" \
    --sf-url "${SF_URL}" \
    --system-key "${SYSTEM_KEY}" \
    --source-name "${SOURCE_NAME}"

# ── Step 7: Start kerbside (reuse start-kerbside.sh) ─────────────────────────
#
# Export the SF token audience so kerbside accepts tokens whose aud equals
# SF's KERBSIDE_URL. start-kerbside.sh hardcodes the DB URL / PUBLIC_FQDN we
# want and passes this through untouched.

export KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE="${AUDIENCE}"
# Belt and braces: the same value start-kerbside.sh sets, exported early so
# the readiness poll below can import kerbside.db before the daemon writes it.
export KERBSIDE_SQL_URL='mysql://kerbside:kerbside@127.0.0.1/kerbside'

echo "[sf-e2e] Starting kerbside via start-kerbside.sh"
"${KERBSIDE_SRC}/tools/direct-qemu/start-kerbside.sh" \
    --sources-path "${SOURCES_PATH}" \
    --tls-dir "${TLS_DIR}" \
    --log-path "${LOG_PATH}" \
    --pid-file "${PID_FILE}" \
    --api-port "${API_PORT}"

# ── Step 8: Write the env file the drivers read ──────────────────────────────

cat > "${KERBSIDE_ENV}" << EOF
KERBSIDE_VENV=${VENV}
KERBSIDE_SRC=${KERBSIDE_SRC}
KERBSIDE_SQL_URL=mysql://kerbside:kerbside@127.0.0.1/kerbside
KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE=${AUDIENCE}
KERBSIDE_SOURCE_NAME=${SOURCE_NAME}
KERBSIDE_RUN_DIR=${RUN_DIR}
KERBSIDE_SOURCES_PATH=${SOURCES_PATH}
KERBSIDE_API_PORT=${API_PORT}
KERBSIDE_SEED_FILE=${SEED_FILE}
KERBSIDE_LOG_PATH=${LOG_PATH}
RYLL_BIN=/usr/local/bin/ryll
SF_URL=${SF_URL}
EOF
echo "[sf-e2e] Wrote ${KERBSIDE_ENV}"

# ── Step 9: Wait for the shakenfist source to become healthy ─────────────────
#
# The daemon's maintenance loop parses sources.yaml and constructs the
# ShakenFistSource, which caches the cluster's signing keys in the DB. When
# those keys are present the source verified the CA and reached the cluster,
# i.e. it is healthy. The test CONSOLE cannot be waited for here -- the
# Sextant instance is imported by a later workflow step -- so the drivers
# poll for the console once it exists.

echo "[sf-e2e] Waiting for the shakenfist source to cache signing keys..."
DEADLINE=$(( $(date +%s) + 180 ))
while true; do
    if "${VENV}/bin/python3" - "${SOURCE_NAME}" << 'PYEOF'
import sys

from kerbside import db

source_name = sys.argv[1]
raw = db.get_sf_token_keys(source_name)
sys.exit(0 if raw else 1)
PYEOF
    then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: shakenfist source did not cache keys within 180s" >&2
        echo "  kerbside daemon log tail:" >&2
        tail -60 "${LOG_PATH}" >&2 || true
        exit 1
    fi
    sleep 3
done

echo "[sf-e2e] kerbside deployed; shakenfist source is healthy"
