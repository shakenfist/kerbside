#!/bin/bash
# Poll the Sextant serial log for the boot banner.
#
# Usage: wait-for-banner.sh SERIAL_LOG [TIMEOUT_SECONDS]
#
# Polls for the literal string "Hello from Uncalibrated Sextant"
# in SERIAL_LOG, sleeping 1 s between checks, up to TIMEOUT_SECONDS
# (default 30).  Exits 0 once the banner appears, 1 on timeout.
#
# Mirrors uncalibrated-sextant/scripts/verify-release.sh:54-65;
# a single-shot grep races OVMF, which routinely takes several
# seconds to enumerate buses and hand off to the bootloader.

set -euo pipefail

SERIAL_LOG="${1:?Usage: $0 SERIAL_LOG [TIMEOUT_SECONDS]}"
TIMEOUT="${2:-30}"
BANNER='Hello from Uncalibrated Sextant'

elapsed=0
while [ "${elapsed}" -lt "${TIMEOUT}" ]; do
    if [ -f "${SERIAL_LOG}" ] && grep -qF "${BANNER}" "${SERIAL_LOG}" 2>/dev/null; then
        echo "[wait-for-banner] banner found after ${elapsed}s"
        exit 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

echo "ERROR: banner not found in ${SERIAL_LOG} within ${TIMEOUT}s" >&2
if [ -f "${SERIAL_LOG}" ]; then
    echo "--- serial log tail ---" >&2
    tail -40 "${SERIAL_LOG}" >&2
else
    echo "  (serial log file does not exist)" >&2
fi
exit 1
