#!/bin/bash
#
# Deploy kerbside on the CI runner, pointed at the Proxmox lane's PVE node.
#
# Runs on the runner, after deploy-proxmox-on-shakenfist and
# tools/proxmox-e2e/prepare-node.sh, in the same job. Kerbside runs on the
# runner as plain processes, as in the oVirt lane: it reaches the node's API
# on 8006 and its spiceproxy on 3128 by the node's FQDN, which the action
# maps in /etc/hosts, so the lane exercises the documented topology of a
# broker on its own host.
#
# The script installs the build prerequisites, creates the kerbside MariaDB
# database, builds a venv holding the pull request's kerbside and its Rust
# proxy wheel, generates proxy TLS material, writes a sources.yaml holding
# one type: proxmox source, records where PVE's access log ends, writes the
# env file the driver reads, starts kerbside by reusing
# tools/direct-qemu/start-kerbside.sh, and waits for the source to leave the
# errored state.
#
# Usage:
#   deploy-kerbside.sh \
#     --api-url       URL   (the action's api_url, https://<fqdn>:8006) \
#     --node-name     NAME  (the action's node_name) \
#     --node-fqdn     FQDN  (the action's node_fqdn) \
#     --node-address  ADDR  (the action's node_address) \
#     --vmid          VMID  (the action's vmid, the SPICE smoke guest) \
#     --ca-file       PATH  (the action's ca_file) \
#     --action-token-id   ID   (the action's token_id) \
#     --action-token-file PATH (the action's token_file) \
#     --lane-file     PATH  (prepare-node.sh's lane-node.json) \
#     --kerbside-src  DIR   (the kerbside checkout to install) \
#     --proxy-wheel   GLOB  (the built kerbside-proxy wheel; expanded here, so
#                            quote it at the call site, and it must match
#                            exactly one file) \
#     [--source-name proxmox] [--api-port 13002] \
#     [--ssh-user debian] [--ssh-key /srv/github/id_ci]
#
# WORKDIR (default /tmp/kerbside-proxmox-ci) is where everything is written.
#
# The source is given only the documented token, from the lane file. The
# action's token is passed to the driver by its ID and file path, so that
# the driver can read the smoke guest's SMBIOS UUID with a token which is
# not kerbside's.
#
# THE ACCESS LOG BASELINE. PVE writes every API request, each spiceproxy
# mint included, to /var/log/pveproxy/access.log on the node. Its size is
# read over ssh just before kerbside starts, and kept in kerbside.env as
# PROXMOX_ACCESS_LOG_OFFSET. drive-console.py counts mints in what PVE
# writes after that point, so the action's own mints, which come before it,
# are not counted. check-privileges.py runs after this script, because it
# needs the venv's requests, so its requests come after the offset. They
# are not counted either: two are made by the single-privilege tokens,
# which are other token IDs, and the count is filtered to the documented
# token's; the third, the documented token's status/stop, is refused, and a
# refused request mints nothing.
#
# THE PROXY'S LOG LEVEL. RUST_LOG is set so that the proxy logs, at debug,
# the two lines of the ryll protocol crate's client that show a backend leg
# was TLS and checked against its pinned subject: "Connecting to ... (TLS:
# true)" and "TLS: certificate subject matches pinned host_subject ...".
# Only that module is raised; the crate names a tunnelled target as
# "(tunnelled, target redacted)", so neither line carries the connect host.
#
# SECURITY: never echoes a token secret, the auth seed or key material. The
# token secret reaches sources.yaml through gen-sources.py, which reads it
# from prepare-node.sh's 0600 file. Do not add set -x. A log which kerbside
# or start-kerbside.sh writes is printed only through redact, below.

set +o xtrace
set -o errexit
set -o nounset
set -o pipefail

fail() {
    echo "::error title=Proxmox lane::$*"
    echo "deploy-kerbside.sh: $*" >&2
    exit 1
}

# Copies standard input to standard output with every value the artifact
# scan looks for, and every connect host, replaced; see drive-console.py's
# redact(). Prints nothing if it fails, never the raw text. Usable once
# the venv exists and kerbside.env is written (step 7).
redact() {
    "${VENV}/bin/python3" "${KERBSIDE_SRC}/tools/proxmox-e2e/drive-console.py" --redact --workdir "${WORKDIR}"
}

API_URL=''
NODE_NAME=''
NODE_FQDN=''
NODE_ADDRESS=''
VMID=''
CA_FILE=''
ACTION_TOKEN_ID=''
ACTION_TOKEN_FILE=''
LANE_FILE=''
KERBSIDE_SRC=''
PROXY_WHEEL=''
SOURCE_NAME='proxmox'
API_PORT='13002'
SSH_USER='debian'
SSH_KEY='/srv/github/id_ci'

while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || fail "$1 needs a value"
    case "$1" in
        --api-url)           API_URL="$2" ;;
        --node-name)         NODE_NAME="$2" ;;
        --node-fqdn)         NODE_FQDN="$2" ;;
        --node-address)      NODE_ADDRESS="$2" ;;
        --vmid)              VMID="$2" ;;
        --ca-file)           CA_FILE="$2" ;;
        --action-token-id)   ACTION_TOKEN_ID="$2" ;;
        --action-token-file) ACTION_TOKEN_FILE="$2" ;;
        --lane-file)         LANE_FILE="$2" ;;
        --kerbside-src)      KERBSIDE_SRC="$2" ;;
        --proxy-wheel)       PROXY_WHEEL="$2" ;;
        --source-name)       SOURCE_NAME="$2" ;;
        --api-port)          API_PORT="$2" ;;
        --ssh-user)          SSH_USER="$2" ;;
        --ssh-key)           SSH_KEY="$2" ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift 2
done

for name in API_URL NODE_NAME NODE_FQDN NODE_ADDRESS VMID CA_FILE ACTION_TOKEN_ID ACTION_TOKEN_FILE \
        LANE_FILE KERBSIDE_SRC PROXY_WHEEL; do
    [ -n "${!name}" ] || fail "--$(echo "${name,,}" | tr _ -) is required"
done
# These end up in commands run on the node, and in the env file.
[[ "${NODE_ADDRESS}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "--node-address is not an IPv4 address: ${NODE_ADDRESS}"
[[ "${VMID}" =~ ^[0-9]+$ ]] || fail "--vmid is not a number: ${VMID}"
[[ "${NODE_NAME}" =~ ^[A-Za-z0-9-]+$ ]] || fail "--node-name is not a node name: ${NODE_NAME}"
[[ "${NODE_FQDN}" =~ ^[A-Za-z0-9.-]+$ ]] || fail "--node-fqdn is not a host name: ${NODE_FQDN}"
[[ "${SSH_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "--ssh-user is not a user name: ${SSH_USER}"
[[ "${API_PORT}" =~ ^[0-9]+$ ]] || fail "--api-port is not a number: ${API_PORT}"
for file in CA_FILE ACTION_TOKEN_FILE LANE_FILE SSH_KEY; do
    [ -f "${!file}" ] || fail "--$(echo "${file,,}" | tr _ -) is not a file: ${!file}"
done

# --proxy-wheel is a glob, expanded here rather than by the caller, so that
# a path which matches nothing fails in one obvious line rather than
# reaching pip as an unexpanded pattern.
# shellcheck disable=SC2206
PROXY_WHEEL_MATCHES=(${PROXY_WHEEL})
if [ "${#PROXY_WHEEL_MATCHES[@]}" -ne 1 ] || [ ! -f "${PROXY_WHEEL_MATCHES[0]}" ]; then
    echo "  pattern: ${PROXY_WHEEL}" >&2
    echo "  matched: ${PROXY_WHEEL_MATCHES[*]}" >&2
    fail '--proxy-wheel must match exactly one existing wheel'
fi
PROXY_WHEEL="${PROXY_WHEEL_MATCHES[0]}"
echo "[proxmox-e2e] Using proxy wheel ${PROXY_WHEEL}"

# Loopback traffic to kerbside must bypass the runner's squid, which 503s it
# otherwise, and so must the node. The action has already added the node to
# no_proxy for the job; it is added again here so that this script does not
# depend on that.
export no_proxy="${no_proxy:-},127.0.0.1,localhost,${NODE_FQDN},${NODE_ADDRESS}"
export NO_PROXY="${no_proxy}"

WORKDIR="${WORKDIR:-/tmp/kerbside-proxmox-ci}"
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

ssh_opts=(-i "${SSH_KEY}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)

# Run one command line on the node, as prepare-node.sh does.
node() {
    timeout 120 ssh "${ssh_opts[@]}" "${SSH_USER}@${NODE_ADDRESS}" "$1" < /dev/null
}

# ── Step 1: Install build prerequisites ──────────────────────────────────────

echo "[proxmox-e2e] Installing build prerequisites"
sudo apt-get update
sudo apt-get install -y \
    mariadb-server build-essential cmake pkg-config libssl-dev \
    default-libmysqlclient-dev python3 python3-pip python3-venv \
    curl openssl

# ── Step 2: Create the kerbside MariaDB database and user ────────────────────

echo "[proxmox-e2e] Creating the kerbside MariaDB database and user"
"${KERBSIDE_SRC}/tools/direct-qemu/setup-mariadb.sh"

# ── Step 3: Create the kerbside venv and install ─────────────────────────────
#
# The Proxmox driver needs nothing beyond kerbside's own dependencies: it
# speaks to the API with requests.

echo "[proxmox-e2e] Creating venv at ${VENV}"
python3 -m venv "${VENV}"
"${VENV}/bin/pip" install --quiet --upgrade pip

echo "[proxmox-e2e] Installing kerbside, proxy wheel, gunicorn"
# The proxy wheel puts kerbside-proxy on the venv PATH, so the daemon's
# find_proxy_bin() resolves it exactly as a wheel-installed deployment would.
# Retried because a first-touch package on a caching index mirror can miss
# the cache and report a bogus "no matching distribution" once.
for attempt in 1 2 3; do
    if "${VENV}/bin/pip" install --quiet "${KERBSIDE_SRC}" "${PROXY_WHEEL}" gunicorn; then
        break
    fi
    [ "${attempt}" != 3 ] || fail 'pip install failed after 3 attempts'
    echo "[proxmox-e2e] pip install failed, retrying (attempt ${attempt}/3)" >&2
    sleep 10
done

# start-kerbside.sh invokes gunicorn, kerbside and python3 bare, so they must
# resolve from the venv.
export PATH="${VENV}/bin:${PATH}"

# ── Step 4: Generate proxy TLS material ──────────────────────────────────────

echo "[proxmox-e2e] Generating proxy TLS material"
"${KERBSIDE_SRC}/tools/direct-qemu/generate-tls.sh" "${TLS_DIR}"

# ── Step 5: Write sources.yaml (one type: proxmox source) ────────────────────

echo "[proxmox-e2e] Writing sources.yaml"
"${VENV}/bin/python3" "${KERBSIDE_SRC}/tools/proxmox-e2e/gen-sources.py" \
    --output "${SOURCES_PATH}" \
    --api-url "${API_URL}" \
    --lane-file "${LANE_FILE}" \
    --ca-file "${CA_FILE}" \
    --source-name "${SOURCE_NAME}" \
    || fail 'could not write sources.yaml (the reason is above)'

# ── Step 6: Record where PVE's access log ends ───────────────────────────────

ACCESS_LOG_OFFSET="$(node 'sudo -n stat -c %s /var/log/pveproxy/access.log')" \
    || fail "could not read the size of the node's access log"
[[ "${ACCESS_LOG_OFFSET}" =~ ^[0-9]+$ ]] || fail "the node's access log size is not a number: ${ACCESS_LOG_OFFSET}"
echo "[proxmox-e2e] PVE's access log is ${ACCESS_LOG_OFFSET} bytes before kerbside starts"

# ── Step 7: Write the env file the driver reads ──────────────────────────────
#
# Written before kerbside starts, so that drive-console.py --scan-only can
# find every secret it scans the artifacts for even when the start fails.
# It holds paths and IDs only, never a secret: this file is uploaded. The
# only credential in it is the well-known loopback MariaDB one, hardcoded
# in tools/direct-qemu/start-kerbside.sh and already public. Anything added
# here must clear that same bar.

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
PROXMOX_API_URL=${API_URL}
PROXMOX_NODE_NAME=${NODE_NAME}
PROXMOX_NODE_FQDN=${NODE_FQDN}
PROXMOX_NODE_ADDRESS=${NODE_ADDRESS}
PROXMOX_VMID=${VMID}
PROXMOX_CA_FILE=${CA_FILE}
PROXMOX_ACTION_TOKEN_ID=${ACTION_TOKEN_ID}
PROXMOX_ACTION_TOKEN_FILE=${ACTION_TOKEN_FILE}
PROXMOX_LANE_FILE=${LANE_FILE}
PROXMOX_SSH_USER=${SSH_USER}
PROXMOX_SSH_KEY=${SSH_KEY}
PROXMOX_ACCESS_LOG_OFFSET=${ACCESS_LOG_OFFSET}
EOF
echo "[proxmox-e2e] Wrote ${KERBSIDE_ENV}"

# ── Step 8: Start kerbside (reuse start-kerbside.sh) ─────────────────────────

# The same value start-kerbside.sh sets, exported early so the readiness
# poll below can import kerbside.db.
export KERBSIDE_SQL_URL='mysql://kerbside:kerbside@127.0.0.1/kerbside'
# Inherited by the proxy, which the daemon launches; see THE PROXY'S LOG
# LEVEL above.
export RUST_LOG='info,shakenfist_spice_protocol::client=debug'

# start-kerbside.sh prints tails of kerbside's logs on a failure, so its
# stderr is held in a file, which is not uploaded, and printed redacted.
START_STDERR="${WORKDIR}/start-kerbside.stderr"
echo "[proxmox-e2e] Starting kerbside via start-kerbside.sh"
START_RC=0
"${KERBSIDE_SRC}/tools/direct-qemu/start-kerbside.sh" \
    --sources-path "${SOURCES_PATH}" \
    --tls-dir "${TLS_DIR}" \
    --log-path "${LOG_PATH}" \
    --pid-file "${PID_FILE}" \
    --api-port "${API_PORT}" 2> "${START_STDERR}" || START_RC=$?
redact < "${START_STDERR}" >&2 || true
[ "${START_RC}" -eq 0 ] || fail "start-kerbside.sh failed (exit ${START_RC})"

# ── Step 9: Wait for the proxmox source to leave the errored state ───────────
#
# daemon_run() parses sources.yaml and runs the first scrape synchronously
# before it launches the proxy, and start-kerbside.sh has already waited for
# the proxy's listener, so the errored flag reflects a real verdict by now.
# A scrape whose request fails (an unreachable API, a CA which does not
# verify, a token PVE refuses) errors the source, and the driver logs which
# request failed, so on timeout the daemon log holds the answer. The
# maintenance loop retries about once a minute, so a slow first round is
# given a few more.

echo "[proxmox-e2e] Waiting for the proxmox source to become non-errored..."
DEADLINE=$(( $(date +%s) + 180 ))
while true; do
    if "${VENV}/bin/python3" - "${SOURCE_NAME}" << 'PYEOF'
import sys

from kerbside import db

source = db.get_source(sys.argv[1])
sys.exit(0 if source and not source.get('errored') else 1)
PYEOF
    then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "  kerbside daemon log tail:" >&2
        tail -60 "${LOG_PATH}" | redact >&2 || true
        fail "the proxmox source ${SOURCE_NAME} did not become healthy within 180s"
    fi
    sleep 3
done

echo "[proxmox-e2e] kerbside deployed; the proxmox source is healthy"
