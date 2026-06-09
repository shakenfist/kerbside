#!/bin/bash
# Launch a QEMU guest for the kerbside CI lane.
#
# Usage: start-qemu.sh \
#   --qcow2 PATH \
#   --ovmf-code PATH \
#   --ovmf-vars PATH \
#   --spice-port N \
#   --ticket STR \
#   --serial-log PATH \
#   --pid-file PATH
#
# Backgrounds qemu and writes the PID to --pid-file.
# Falls back to accel=tcg if /dev/kvm is not writable, with a warning.
# Part of docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md step 5b.

set -euo pipefail

QCOW2=''
OVMF_CODE=''
OVMF_VARS=''
SPICE_PORT=''
TICKET=''
SERIAL_LOG=''
PID_FILE=''

while [ $# -gt 0 ]; do
    case "$1" in
        --qcow2)      QCOW2="$2";      shift 2 ;;
        --ovmf-code)  OVMF_CODE="$2";  shift 2 ;;
        --ovmf-vars)  OVMF_VARS="$2";  shift 2 ;;
        --spice-port) SPICE_PORT="$2"; shift 2 ;;
        --ticket)     TICKET="$2";     shift 2 ;;
        --serial-log) SERIAL_LOG="$2"; shift 2 ;;
        --pid-file)   PID_FILE="$2";   shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Validate required args
for arg in QCOW2 OVMF_CODE OVMF_VARS SPICE_PORT TICKET SERIAL_LOG PID_FILE; do
    if [ -z "${!arg}" ]; then
        echo "ERROR: --${arg,,} is required" >&2
        exit 1
    fi
done

if [ ! -f "${QCOW2}" ]; then
    echo "ERROR: qcow2 not found: ${QCOW2}" >&2
    exit 1
fi

if [ ! -f "${OVMF_CODE}" ]; then
    echo "ERROR: OVMF code file not found: ${OVMF_CODE}" >&2
    exit 1
fi

if [ ! -f "${OVMF_VARS}" ]; then
    echo "ERROR: OVMF vars file not found: ${OVMF_VARS}" >&2
    exit 1
fi

# Copy OVMF_VARS to a writable location (qemu writes to it at runtime)
VARS_DIR="$(dirname "${PID_FILE}")"
VARS_COPY="${VARS_DIR}/ovmf-vars-copy.fd"
cp "${OVMF_VARS}" "${VARS_COPY}"

# Determine KVM acceleration
if [ -w /dev/kvm ]; then
    ACCEL='kvm'
    echo "[start-qemu] KVM acceleration enabled"
else
    ACCEL='tcg'
    echo "[start-qemu] WARNING: /dev/kvm not writable; falling back to accel=tcg (slow)" >&2
fi

echo "[start-qemu] Launching QEMU with SPICE on port ${SPICE_PORT}"

qemu-system-x86_64 \
    -machine "q35,accel=${ACCEL}" \
    -m 512 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${VARS_COPY}" \
    -drive "file=${QCOW2},format=qcow2,if=virtio" \
    -vga qxl \
    -spice "port=${SPICE_PORT},password=${TICKET},disable-ticketing=off" \
    -serial "file:${SERIAL_LOG}" \
    -display none \
    -nodefaults \
    -no-reboot \
    -daemonize \
    -pidfile "${PID_FILE}"
# `-vga qxl` is what causes QEMU's SPICE server to advertise the
# display + cursor channels.  Without it the server only exposes
# `inputs` (the implicit keyboard), `surfaces` stays empty on the
# ryll side, and the smoke client times out waiting for a usable
# display.  Mirrors the Sextant reference recipe at
# uncalibrated-sextant/scripts/spice.sh:63.

echo "[start-qemu] QEMU daemonized, pid=$(cat "${PID_FILE}")"
