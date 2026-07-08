#!/bin/bash
# Phase 7: non-gating latency loadtest. Drives the EXISTING latency
# orchestrator (loadtests/latency/orchestrator.py) against the live lane's
# ryll control socket to sample SPICE PING/PONG round-trip time through
# the Rust proxy the lane is running, then summarises
# p50/p95 and records the numbers so the Python-vs-Rust comparison can be read
# off the two matrix legs' artifacts.
#
# This QUANTIFIES the performance claim; it never gates the build. It runs on
# the shared scenario lane (it only sends PINGs and reads latency events, so
# it does not disturb the connection the scenario needs) and is best-effort:
# a measurement hiccup logs a warning and exits 0.
#
# Usage: run-loadtest.sh   (reads the lane defaults from the environment)

set -uo pipefail  # NOT -e: measurement must never fail the lane.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WORKDIR="${WORKDIR:-/tmp/kerbside-ci}"
RYLL_SOCK="${RYLL_SOCK:-${WORKDIR}/ryll-ci.sock}"
PROXY="${LOADTEST_PROXY_LABEL:-rust}"
SAMPLES="${LOADTEST_SAMPLES:-20}"
MAX_SECONDS="${LOADTEST_MAX_SECONDS:-40}"
RESULTS_DIR="${LOADTEST_RESULTS_DIR:-/tmp/loadtest-artifacts}"

mkdir -p "${RESULTS_DIR}"
CSV="${RESULTS_DIR}/latency-${PROXY}.csv"
SUMMARY="${RESULTS_DIR}/latency-${PROXY}.summary.txt"

if [ ! -S "${RYLL_SOCK}" ]; then
    echo "[loadtest] WARNING: ryll control socket ${RYLL_SOCK} not present; skipping" >&2
    exit 0
fi

echo "[loadtest] Sampling ${SAMPLES} RTT samples through the ${PROXY} proxy"
if ! python3 "${REPO_ROOT}/loadtests/latency/orchestrator.py" \
        --socket "${RYLL_SOCK}" \
        --output "${CSV}" \
        --sample-count "${SAMPLES}" \
        --max-seconds "${MAX_SECONDS}"; then
    echo "[loadtest] WARNING: orchestrator exited non-zero; recording whatever samples landed" >&2
fi

# Summarise the CSV (one RTT sample in SECONDS per line) into p50/p95 ms.
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
    line = f'LOADTEST proxy={proxy} rtt_ms samples=0 (no data)'
else:
    samples_ms.sort()

    def pct(p):
        # Nearest-rank percentile; robust for small n.
        k = max(0, min(len(samples_ms) - 1, round(p / 100.0 * len(samples_ms)) - 1))
        return samples_ms[k]

    line = (f'LOADTEST proxy={proxy} rtt_ms samples={len(samples_ms)} '
            f'p50={pct(50):.3f} p95={pct(95):.3f} '
            f'min={samples_ms[0]:.3f} max={samples_ms[-1]:.3f} '
            f'mean={statistics.fmean(samples_ms):.3f}')

with open(summary_path, 'w') as f:
    f.write(line + '\n')
print(line)
PYEOF

echo "[loadtest] summary written to ${SUMMARY}"
exit 0
