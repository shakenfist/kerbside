#!/bin/bash
# Probe the CI runner for KVM, qemu, OVMF, and other dependencies.
#
# Prints diagnostic information and exits non-zero only if /dev/kvm is
# absent (the rest is informational; missing OVMF or cargo are handled
# in later workflow steps).

set -uo pipefail

echo "=== /dev/kvm ==="
if [ -e /dev/kvm ]; then
    ls -la /dev/kvm
else
    echo "ERROR: /dev/kvm does not exist on this runner" >&2
    exit 1
fi

echo ""
echo "=== KVM kernel modules ==="
lsmod | grep -E '^(kvm|kvm_intel|kvm_amd)' || true

echo ""
echo "=== qemu-system-x86_64 ==="
if command -v qemu-system-x86_64 > /dev/null 2>&1; then
    qemu-system-x86_64 --version
    command -v qemu-system-x86_64
else
    echo "(not installed yet — will be installed in next step)"
fi

echo ""
echo "=== OVMF firmware paths ==="
for dir in /usr/share/OVMF /usr/share/ovmf; do
    if [ -d "${dir}" ]; then
        echo "Found ${dir}:"
        ls -la "${dir}/" || true
    else
        echo "${dir}: not found"
    fi
done

echo ""
echo "=== Rust / cargo ==="
if command -v cargo > /dev/null 2>&1; then
    command -v cargo
    cargo --version
else
    echo "(cargo not found — will install via rustup)"
fi

echo ""
echo "=== Python 3 ==="
python3 --version

echo ""
echo "=== Sextant qcow2 fixture ==="
sha256sum tests/fixtures/uncalibrated-sextant.qcow2

echo ""
echo "=== probe-runner complete ==="
