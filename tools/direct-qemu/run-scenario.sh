#!/bin/bash
# Run the Sextant scenario tempest test against a live direct-qemu lane.
#
# This is the final lane step.  It is deliberately destructive: the scenario
# drives Sextant all the way to the Parked screen and then sends a keypress
# that makes the guest drain serial and ACPI-shutdown.  qemu exits, ryll's
# event loop ends, and the control socket is unlinked.  Nothing in the lane is
# usable afterwards, so this MUST be the last step that runs on a lane.
#
# Credential-less tempest does not work through the `tempest run` CLI -- it
# insists on a workspace / cloud config. The working invocation is stestr
# pointed at the plugin's test path with TEMPEST_CONFIG exported (resolved
# empirically). The plugin is installed NON-editable: `pip install -e` drops a
# _version.py into the source tree, which pollutes the checkout.

set -euo pipefail

# ── Lane parameters (override via env) ───────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WORKDIR="${WORKDIR:-/tmp/kerbside-ci}"
TEMPEST_VENV="${TEMPEST_VENV:-/tmp/tempest-venv}"
# The tempest.conf must live OUTSIDE WORKDIR: lane-down.sh removes that tree,
# and stestr/oslo lock files should not be torn out from under a running test.
TEMPEST_ETC="${TEMPEST_ETC:-/tmp/tempest-etc}"

# The four [kerbside] values are derived from WORKDIR so they track the lane.
CONTROL_SOCKET_PATH="${CONTROL_SOCKET_PATH:-${WORKDIR}/ryll-ci.sock}"
SERIAL_LOG_PATH="${SERIAL_LOG_PATH:-${WORKDIR}/sextant-serial.log}"
SCENARIO_ARTIFACT_DIR="${SCENARIO_ARTIFACT_DIR:-${WORKDIR}/scenario}"
SCENARIO_STEP_TIMEOUT="${SCENARIO_STEP_TIMEOUT:-60}"

LOCK_PATH="${LOCK_PATH:-/tmp/kerbside-lock}"

# ── Step 1: Build the tempest venv (separate from the kerbside venv) ──────────
#
# tempest's oslo/paste dependency train conflicts easily with kerbside's
# pinned requirements, so it gets its own venv.

if [ ! -x "${TEMPEST_VENV}/bin/python" ]; then
    echo "[run-scenario] Creating tempest venv at ${TEMPEST_VENV}"
    python3 -m venv "${TEMPEST_VENV}"
fi

echo "[run-scenario] Installing tempest"
"${TEMPEST_VENV}/bin/pip" install --quiet tempest

echo "[run-scenario] Installing kerbside tempest plugin (non-editable)"
"${TEMPEST_VENV}/bin/pip" install --quiet "${REPO_ROOT}/tempest-plugin"

# ── Step 2: Write the minimal tempest.conf ───────────────────────────────────

echo "[run-scenario] Writing tempest.conf to ${TEMPEST_ETC}/tempest.conf"
mkdir -p "${TEMPEST_ETC}" "${LOCK_PATH}" "${SCENARIO_ARTIFACT_DIR}"

cat > "${TEMPEST_ETC}/tempest.conf" << EOF
[oslo_concurrency]
lock_path = ${LOCK_PATH}
[kerbside]
control_socket_path = ${CONTROL_SOCKET_PATH}
serial_log_path = ${SERIAL_LOG_PATH}
scenario_artifact_dir = ${SCENARIO_ARTIFACT_DIR}
scenario_step_timeout = ${SCENARIO_STEP_TIMEOUT}
EOF

# ── Step 3: Run the scenario test via stestr ─────────────────────────────────
#
# stestr needs a writable cwd for its .stestr directory; the plugin checkout
# is fine.  TEMPEST_CONFIG_DIR / TEMPEST_CONFIG point oslo.config at our conf.

cd "${REPO_ROOT}/tempest-plugin"
export TEMPEST_CONFIG_DIR="${TEMPEST_ETC}"
export TEMPEST_CONFIG='tempest.conf'

echo "[run-scenario] Running the Sextant scenario test"
"${TEMPEST_VENV}/bin/stestr" \
    --test-path ./kerbside_tempest_plugin/tests \
    run --serial 'test_sextant_scenario'
