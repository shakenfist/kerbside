#!/bin/bash
# Non-gating keypress-to-screen latency loadtest on a DEDICATED, throwaway
# lane.
#
# The orchestrator (loadtests/latency/orchestrator.py) measures the
# user-perceivable metric: a cadence thread injects real `send_key` events and
# times the `surface_drawn` event each one produces through the Rust proxy the
# lane is running, then this script summarises p50/p95 and records the numbers
# so the Python-vs-Rust comparison can be read off the two matrix legs'
# artifacts.
#
# Injecting keypresses is DESTRUCTIVE to guest state -- it drives the Sextant
# fixture off its Awaiting screen and through boot -- so this must NOT run on
# the shared scenario lane the way the old PING/PONG probe did. Instead, like
# verify-terminate-live.sh, it brings up its OWN isolated lane (a separate
# WORKDIR), measures, and tears the lane down again. The Sextant scenario test
# that follows therefore inherits a pristine guest sitting on the Awaiting
# screen with a live QR digest stream.
#
# Self-contained and best-effort: it never gates the build (continue-on-error
# in CI, and this script always exits 0). Ports are the lane defaults; this
# runs to completion and tears down -- freeing the ports -- before the shared
# scenario lane comes up, so there is no conflict. Same prerequisites as
# lane-up.sh (qemu, the Sextant qcow2, MariaDB, a resolvable kerbside-proxy).
#
# Usage: run-loadtest.sh   (reads the lane defaults from the environment)

set -uo pipefail  # NOT -e: measurement must never fail the lane.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Dedicated lane, isolated from the scenario lane's /tmp/kerbside-ci so it
# neither clobbers nor is clobbered by it.
export WORKDIR="${LOADTEST_WORKDIR:-/tmp/kerbside-loadtest}"
RYLL_SOCK="${WORKDIR}/ryll-ci.sock"
SERIAL_LOG="${WORKDIR}/sextant-serial.log"

# Boot the purpose-built latency guest, not the Sextant scenario fixture. The
# uefi-latency-guest image repaints on every keypress and never advances
# through irreversible scene states, so the cadence keypresses produce a
# `surface_drawn` each and the run collects a full sample set -- whereas
# Sextant leaves its Awaiting screen on the first key and freezes at the
# bootloader prompt.
export QCOW2="${LOADTEST_QCOW2:-${REPO_ROOT}/tests/fixtures/uefi-latency-guest.qcow2}"

PROXY="${LOADTEST_PROXY_LABEL:-rust}"
SAMPLES="${LOADTEST_SAMPLES:-20}"
MAX_SECONDS="${LOADTEST_MAX_SECONDS:-40}"
BANNER_TIMEOUT="${LOADTEST_BANNER_TIMEOUT:-30}"
RESULTS_DIR="${LOADTEST_RESULTS_DIR:-/tmp/loadtest-artifacts}"

mkdir -p "${RESULTS_DIR}"
CSV="${RESULTS_DIR}/latency-${PROXY}.csv"
SUMMARY="${RESULTS_DIR}/latency-${PROXY}.summary.txt"

# Always tear the lane down, and stash the ryll/serial logs first -- they live
# inside WORKDIR (which lane-down removes) so copying them into RESULTS_DIR is
# what keeps a measurement hiccup debuggable from the uploaded artifacts.
# shellcheck disable=SC2317  # invoked indirectly via the EXIT trap below
cleanup() {
    for name in ryll-ci.stdout ryll-ci.stderr sextant-serial.log; do
        if [ -f "${WORKDIR}/${name}" ]; then
            cp "${WORKDIR}/${name}" "${RESULTS_DIR}/loadtest-${name}" 2>/dev/null || true
        fi
    done
    WORKDIR="${WORKDIR}" "${SCRIPT_DIR}/lane-down.sh" || true
}
trap cleanup EXIT

echo "[loadtest] Bringing up a dedicated loadtest lane in ${WORKDIR}"
if ! "${SCRIPT_DIR}/lane-up.sh"; then
    echo "[loadtest] WARNING: lane-up failed; skipping loadtest" >&2
    exit 0
fi

echo "[loadtest] Waiting for the Sextant boot banner"
if ! "${SCRIPT_DIR}/wait-for-banner.sh" "${SERIAL_LOG}" "${BANNER_TIMEOUT}"; then
    echo "[loadtest] WARNING: boot banner did not appear; skipping loadtest" >&2
    exit 0
fi

echo "[loadtest] Sampling ${SAMPLES} keypress-to-screen latencies through the ${PROXY} proxy"
if ! python3 "${REPO_ROOT}/loadtests/latency/orchestrator.py" \
        --socket "${RYLL_SOCK}" \
        --output "${CSV}" \
        --sample-count "${SAMPLES}" \
        --max-seconds "${MAX_SECONDS}"; then
    echo "[loadtest] WARNING: orchestrator exited non-zero; recording whatever samples landed" >&2
fi

# Summarise the CSV (one keypress-to-screen sample in SECONDS per line) into
# p50/p95 ms.
python3 - "${CSV}" "${SUMMARY}" "${PROXY}" << 'PYEOF'
import statistics
import sys

csv_path, summary_path, proxy = sys.argv[1], sys.argv[2], sys.argv[3]
samples_ms = []
try:
    with open(csv_path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples_ms.append(float(line) * 1000.0)
except FileNotFoundError:
    pass

if not samples_ms:
    line = f'LOADTEST proxy={proxy} latency_ms samples=0 (no data)'
else:
    samples_ms.sort()

    def pct(p):
        # Nearest-rank percentile; robust for small n.
        k = max(0, min(len(samples_ms) - 1, round(p / 100.0 * len(samples_ms)) - 1))
        return samples_ms[k]

    line = (f'LOADTEST proxy={proxy} latency_ms samples={len(samples_ms)} '
            f'p50={pct(50):.3f} p95={pct(95):.3f} '
            f'min={samples_ms[0]:.3f} max={samples_ms[-1]:.3f} '
            f'mean={statistics.fmean(samples_ms):.3f}')

with open(summary_path, 'w') as f:
    f.write(line + '\n')
print(line)
PYEOF

echo "[loadtest] summary written to ${SUMMARY}"
exit 0
