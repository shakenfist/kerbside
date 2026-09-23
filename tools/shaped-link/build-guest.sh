#!/bin/bash
# Build the keydraw guest used by the shaped-link latency rig: a kernel
# plus an initrd whose /init is guest/keydraw.c, statically linked.
#
# Usage: build-guest.sh OUTDIR
#
# The guest reuses the host's own kernel (/boot/vmlinuz-$(uname -r)) and
# takes the handful of modules it needs (virtio-gpu and its helpers,
# evdev) from /lib/modules/$(uname -r), so there is nothing to download.
# It needs gcc with a static glibc, and cpio. Writes OUTDIR/vmlinuz and
# OUTDIR/initrd.gz.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${1:?usage: build-guest.sh OUTDIR}"
KVER="${KVER:-$(uname -r)}"
KERNEL="${KERNEL:-/boot/vmlinuz-${KVER}}"
MODDIR="/lib/modules/${KVER}/kernel"

MODULES=(
    drivers/virtio/virtio_dma_buf.ko.xz
    drivers/gpu/drm/drm.ko.xz
    drivers/gpu/drm/drm_kms_helper.ko.xz
    drivers/gpu/drm/drm_shmem_helper.ko.xz
    drivers/gpu/drm/virtio/virtio-gpu.ko.xz
    drivers/input/evdev.ko.xz
)

if [ ! -r "${KERNEL}" ]; then
    echo "ERROR: kernel ${KERNEL} is not readable; set KERNEL= and KVER=" >&2
    exit 1
fi

mkdir -p "${OUTDIR}"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT
mkdir -p "${ROOT}/m"

gcc -O2 -static -Wall -Wextra -o "${ROOT}/init" \
    "${SCRIPT_DIR}/guest/keydraw.c" -lm
for mod in "${MODULES[@]}"; do
    if [ ! -f "${MODDIR}/${mod}" ]; then
        echo "ERROR: module ${MODDIR}/${mod} not found" >&2
        exit 1
    fi
    cp "${MODDIR}/${mod}" "${ROOT}/m/"
done

(cd "${ROOT}" && find . | cpio --quiet -o -H newc -R 0:0) \
    | gzip -9 > "${OUTDIR}/initrd.gz"
cp "${KERNEL}" "${OUTDIR}/vmlinuz"
echo "[build-guest] wrote ${OUTDIR}/vmlinuz and ${OUTDIR}/initrd.gz (kernel ${KVER})"
