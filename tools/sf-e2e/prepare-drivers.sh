#!/bin/bash
# Prepare the Shaken Fist primary for the sf-e2e drivers.
#
# Runs ON the SF primary, as the CI user, after build-smoke-cluster has
# deployed Kerbside there with the shakenfist.kerbside collection's kerbside
# role (tools/sf-e2e/deploy-profile.yml.j2 asks for it). By then Kerbside is
# running as the kerbside-api and kerbside-daemon systemd units, and the role
# has waited for its Shaken Fist source to fetch the console token signing
# keys. This script:
#
#   * builds ryll from source with the digest-decode feature, which is what
#     lets the happy path drive the Sextant on-screen visual digest through
#     ryll's control socket; and
#   * writes /tmp/sf-e2e/kerbside.env, which tells the drivers where the role
#     put Kerbside and how it is configured.
#
# The role writes /etc/kerbside/kerbside.ini and /etc/kerbside/sources.yaml
# owned by root and readable only by the kerbside group, in a directory only
# that group may enter. This script leaves them exactly so: it reads them with
# sudo, and the workflow runs the drivers with sudo for the same reason.
#
# Usage:
#   prepare-drivers.sh \
#     [--kerbside-src DIR] (the copied kerbside checkout on the primary,
#                           default /tmp/sf-e2e/kerbside) \
#     [--sf-url http://localhost:13000] \
#     [--api-port 13002]   (the role's kerbside_api_port)
#
# SECURITY: never echoes the SQL URL, the auth seed, a source password, or
# key material. kerbside.env carries the SQL URL, so it is written 0600; the
# auth seed goes to its own root-owned 0600 file, which the happy path reads.
# Neither is ever gathered as an artifact.

set -euo pipefail

KERBSIDE_SRC='/tmp/sf-e2e/kerbside'
SF_URL='http://localhost:13000'
API_PORT='13002'

while [ $# -gt 0 ]; do
    case "$1" in
        --kerbside-src) KERBSIDE_SRC="$2"; shift 2 ;;
        --sf-url)       SF_URL="$2";       shift 2 ;;
        --api-port)     API_PORT="$2";     shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Where the kerbside role puts things: kerbside_venv and kerbside_config_dir,
# which deploy-profile.yml.j2 pins. Change them there and here together.
VENV='/srv/kerbside/venv'
CONFIG_DIR='/etc/kerbside'
INI_PATH="${CONFIG_DIR}/kerbside.ini"
SOURCES_PATH="${CONFIG_DIR}/sources.yaml"

SF_E2E_ROOT='/tmp/sf-e2e'
RUN_DIR="${SF_E2E_ROOT}/run"
SEED_FILE="${RUN_DIR}/kerbside-auth-seed.txt"
KERBSIDE_ENV="${SF_E2E_ROOT}/kerbside.env"
RYLL_BIN='/usr/local/bin/ryll'

mkdir -p "${RUN_DIR}"

# ── Step 1: Install ryll's build prerequisites ───────────────────────────────

echo "[sf-e2e] Installing ryll's build prerequisites"
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config libssl-dev curl openssl

# ── Step 2: Build ryll from source with digest-decode ────────────────────────
#
# Mirrors direct-qemu-functional.yml's "Ensure Rust toolchain" + "Build ryll
# from main" steps.

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
    sudo install -m 755 target/release/ryll "${RYLL_BIN}"
)
"${RYLL_BIN}" --version || true

# ── Step 3: Write the env file the drivers read ──────────────────────────────
#
# The values come from the files the role wrote, so the drivers see the
# Kerbside which is actually running rather than a second copy of the deploy
# profile. The role's venv has PyYAML, since Kerbside reads sources.yaml with
# it. Python writes both files itself, so no secret passes through this
# shell, its arguments or its output; it hands kerbside.env to the user who
# ran sudo, so that import-instance.sh can read it without sudo.

echo "[sf-e2e] Writing ${KERBSIDE_ENV} from the role's configuration"
sudo "${VENV}/bin/python3" - \
    "${INI_PATH}" "${SOURCES_PATH}" "${KERBSIDE_ENV}" "${SEED_FILE}" \
    "${VENV}" "${KERBSIDE_SRC}" "${RUN_DIR}" "${API_PORT}" "${RYLL_BIN}" \
    "${SF_URL}" << 'PYEOF'
import configparser
import os
import sys

import yaml

(ini_path, sources_path, env_path, seed_path, venv, kerbside_src, run_dir,
 api_port, ryll_bin, sf_url) = sys.argv[1:]


def write_private(path, text, uid=0, gid=0):
    """Write text to path, 0600 and owned by uid:gid, even if it existed."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        os.fchown(f.fileno(), uid, gid)
        f.write(text)


# Kerbside reads kerbside.ini with interpolation off, so it is read the same
# way here.
ini = configparser.ConfigParser(interpolation=None)
if not ini.read(ini_path):
    sys.exit('[sf-e2e] ERROR: the role wrote no %s' % ini_path)
settings = ini['kerbside']

with open(sources_path) as f:
    sources = yaml.safe_load(f) or []
names = [str(s['source']) for s in sources if s.get('type') == 'shakenfist']
if len(names) != 1:
    sys.exit('[sf-e2e] ERROR: expected one shakenfist source in %s, found %d'
             % (sources_path, len(names)))

write_private(seed_path, settings['auth_secret_seed'])

env = [
    ('KERBSIDE_VENV', venv),
    ('KERBSIDE_SRC', kerbside_src),
    ('KERBSIDE_SQL_URL', settings['sql_url']),
    ('KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE',
     settings['sf_console_token_audience']),
    ('KERBSIDE_SOURCE_NAME', names[0]),
    ('KERBSIDE_RUN_DIR', run_dir),
    ('KERBSIDE_SOURCES_PATH', sources_path),
    ('KERBSIDE_API_PORT', api_port),
    ('KERBSIDE_SEED_FILE', seed_path),
    ('RYLL_BIN', ryll_bin),
    ('SF_URL', sf_url),
]
write_private(env_path, ''.join('%s=%s\n' % kv for kv in env),
              int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))

# Only facts which are not secret.
print('[sf-e2e] wrote %s (source=%s, audience=%s)'
      % (env_path, names[0], settings['sf_console_token_audience']))
PYEOF

echo "[sf-e2e] The primary is ready for the drivers"
