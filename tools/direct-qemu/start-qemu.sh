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
#   --pid-file PATH \
#   [--tls-port N --x509-dir PATH]
#
# Backgrounds qemu and writes the PID to --pid-file.
# Falls back to accel=tcg if /dev/kvm is not writable, with a warning.
#
# --tls-port/--x509-dir (must be given together) additionally open a SPICE
# TLS listener with tls-channel=default, so every channel REQUIRES TLS: a
# plaintext connect on --spice-port receives the SPICE need_secured reply
# and must retry on the TLS port -- exactly how a production hypervisor
# with SPICE TLS behaves, and the path the kerbside proxy's backend leg
# implements. --x509-dir must contain qemu's fixed filenames ca-cert.pem,
# server-cert.pem, and server-key.pem (see generate-tls.sh's qemu-x509/).

set -euo pipefail

QCOW2=''
OVMF_CODE=''
OVMF_VARS=''
SPICE_PORT=''
TICKET=''
SERIAL_LOG=''
PID_FILE=''
TLS_PORT=''
X509_DIR=''

while [ $# -gt 0 ]; do
    case "$1" in
        --qcow2)      QCOW2="$2";      shift 2 ;;
        --ovmf-code)  OVMF_CODE="$2";  shift 2 ;;
        --ovmf-vars)  OVMF_VARS="$2";  shift 2 ;;
        --spice-port) SPICE_PORT="$2"; shift 2 ;;
        --ticket)     TICKET="$2";     shift 2 ;;
        --serial-log) SERIAL_LOG="$2"; shift 2 ;;
        --pid-file)   PID_FILE="$2";   shift 2 ;;
        --tls-port)   TLS_PORT="$2";   shift 2 ;;
        --x509-dir)   X509_DIR="$2";   shift 2 ;;
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

# --tls-port and --x509-dir come as a pair.
if [ -n "${TLS_PORT}" ] || [ -n "${X509_DIR}" ]; then
    if [ -z "${TLS_PORT}" ] || [ -z "${X509_DIR}" ]; then
        echo "ERROR: --tls-port and --x509-dir must be given together" >&2
        exit 1
    fi
    for f in ca-cert.pem server-cert.pem server-key.pem; do
        if [ ! -f "${X509_DIR}/${f}" ]; then
            echo "ERROR: ${X509_DIR}/${f} not found (see generate-tls.sh)" >&2
            exit 1
        fi
    done
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

SPICE_OPTS="port=${SPICE_PORT},password-secret=spice-ticket,disable-ticketing=off"
if [ -n "${TLS_PORT}" ]; then
    # tls-channel=default makes TLS the required policy for every channel:
    # a plaintext connect on ${SPICE_PORT} gets the SPICE need_secured
    # reply instead of a session, forcing clients (and the kerbside
    # proxy's backend leg) onto the TLS port.
    SPICE_OPTS+=",tls-port=${TLS_PORT},x509-dir=${X509_DIR},tls-channel=default"
    echo "[start-qemu] SPICE TLS enabled on port ${TLS_PORT} (x509-dir=${X509_DIR})"
fi

echo "[start-qemu] Launching QEMU with SPICE on port ${SPICE_PORT}"

qemu-system-x86_64 \
    -machine "q35,accel=${ACCEL}" \
    -m 512 \
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
    -drive "if=pflash,format=raw,file=${VARS_COPY}" \
    -drive "file=${QCOW2},format=qcow2" \
    -vga qxl \
    -object "secret,id=spice-ticket,data=${TICKET}" \
    -spice "${SPICE_OPTS}" \
    -serial "file:${SERIAL_LOG}" \
    -display none \
    -no-reboot \
    -daemonize \
    -pidfile "${PID_FILE}"
# The SPICE ticket is supplied via `-object secret` +
# `password-secret=` because the legacy inline `password=` parameter
# was removed in newer QEMU releases (it fails on QEMU 10 with
# "Invalid parameter 'password'").  `password-secret` has been
# supported since QEMU 5.2, so this form works on the debian-12 CI
# runner (QEMU 7.2) and on newer developer hosts alike.
# `-nodefaults` was previously set but removes the implicit AHCI
# controller on q35.  With a bare `-drive format=qcow2,file=...`
# (no `if=` modifier, so QEMU defaults to `if=ide`), there is no
# bus to attach the disk to and OVMF drops to the firmware menu
# instead of booting Sextant.  Sextant's own verify-release.sh
# and spice.sh both omit `-nodefaults`, so do the same here.
# `-vga qxl` is what causes QEMU's SPICE server to advertise the
# display + cursor channels.  Without it the server only exposes
# `inputs` (the implicit keyboard), `surfaces` stays empty on the
# ryll side, and the smoke client times out waiting for a usable
# display.  Mirrors the Sextant reference recipe at
# uncalibrated-sextant/scripts/spice.sh:63.

echo "[start-qemu] QEMU daemonized, pid=$(cat "${PID_FILE}")"
