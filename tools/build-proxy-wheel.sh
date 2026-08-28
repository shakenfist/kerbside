#!/bin/bash
#
# Build a manylinux wheel for the kerbside-proxy crate for one target
# architecture. Used by the release workflow's wheel matrix (x86_64 and
# aarch64) and reproducible locally.
#
# Usage:
#   tools/build-proxy-wheel.sh x86_64     # cross/native manylinux (release)
#   tools/build-proxy-wheel.sh aarch64    # cross manylinux (release)
#   tools/build-proxy-wheel.sh --native   # plain host wheel, for local install
#
# Output wheels land in ${WHEEL_OUT:-<repo>/dist/proxy-wheels}.
#
# APPROACH: both architectures are built with maturin's `--zig` linker and
# `--compatibility manylinux_2_28`. zig supplies a pinned-glibc (2.28)
# sysroot, so the produced wheel honestly carries a manylinux_2_28 tag even
# when the build host has a newer glibc, and aarch64 is cross-compiled from
# an x86_64 host with no emulation. The vendored protoc (protoc-bin-vendored)
# runs on the BUILD host, so cross-compilation does not touch it.
#
# PREREQUISITES (provided by the caller/CI, not installed here):
#   - a Rust toolchain with rustup (the release workflow uses
#     dtolnay/rust-toolchain; the local Docker path uses the official rust
#     image). The target std library is added idempotently below.
#   - maturin and the `ziglang` Python package on PATH / importable
#     (`pip install maturin ziglang`).
#
# The build MUST run with the repository root available, because the crate's
# build.rs compiles ../../kerbside/rpc/kerbside.proto. This script cd's into
# the crate directory within the repo to satisfy that.
#
# FALLBACK (documented, not automated): if the zig cross of the
# ring/rustls/ryll dependency chain ever fails for aarch64, build the aarch64
# wheel inside the quay.io/pypa/manylinux_2_28_aarch64 image under
# binfmt/QEMU emulation instead (slower, but the canonical manylinux path).

# NATIVE MODE (--native): build a plain host-arch wheel with no zig, no forced
# manylinux tag, and no rustup target. This is for callers that build and
# INSTALL the wheel on the same machine (the direct-qemu Rust lane), where
# portability is irrelevant -- so it needs only maturin + a host cargo, not
# rustup/ziglang. Release wheels for distribution still use the per-arch
# manylinux/zig path above.

set -euo pipefail

native=0
arch="${1:-}"
case "${arch}" in
    x86_64)   triple="x86_64-unknown-linux-gnu" ;;
    aarch64)  triple="aarch64-unknown-linux-gnu" ;;
    --native) native=1 ;;
    *)
        echo "Usage: $0 <x86_64|aarch64|--native>" >&2
        exit 1
        ;;
esac

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
crate_dir="${repo_root}/rust/kerbside-proxy"
wheel_out="${WHEEL_OUT:-${repo_root}/dist/proxy-wheels}"

command -v maturin >/dev/null || { echo "ERROR: maturin not found on PATH" >&2; exit 1; }

mkdir -p "${wheel_out}"
cd "${crate_dir}"

# If the tree is unstamped (pyproject.toml still declares a dynamic version,
# which maturin resolves from Cargo.toml's 0.1.0 placeholder), stamp the
# setuptools_scm dev version first. kerbside's committed dependency floor
# (kerbside-proxy>=X.Y.Z.dev0) rejects a 0.1.0 wheel, so an unstamped local
# wheel cannot be co-installed with kerbside. The stamp is reverted on exit
# so the working tree is left as found. Requires setuptools_scm and full git
# history (a shallow clone cannot count commits since the last v* tag).
#
# This block CANNOT fire on a release build: tools/stamp-proxy-version.sh
# replaces the `dynamic = ["version"]` declaration with a static release
# version, so on a release-stamped tree the grep below does not match. The
# tree state, not call ordering, is what keeps the two stamp modes apart
# (tools/verify-wheel-stamping.sh asserts both modes in CI).
# Anchored at both ends deliberately: tools/stamp-proxy-version.sh and
# tools/stamp-dev-proxy-version.sh test this same line in this same file, and
# all three must agree about whether the tree is stamped.
if grep -q '^dynamic = \["version"\]$' pyproject.toml; then
    echo "Unstamped tree: stamping the setuptools_scm dev version..."
    saved_pyproject="$(mktemp)"
    cp pyproject.toml "${saved_pyproject}"
    restore_pyproject() {
        cat "${saved_pyproject}" > pyproject.toml
        rm -f "${saved_pyproject}"
    }
    trap restore_pyproject EXIT
    "${repo_root}/tools/stamp-dev-proxy-version.sh"
fi

if [ "${native}" = 1 ]; then
    echo "Building kerbside-proxy wheel for the host (native, no zig/manylinux)..."
    maturin build --release --out "${wheel_out}"
    # Accept whatever platform tag maturin produces for the host; a native
    # host wheel is not required to be manylinux-tagged. Wheel filenames
    # cannot contain whitespace, so ls -t is a safe way to pick the newest.
    # shellcheck disable=SC2012
    wheel="$(ls -1t "${wheel_out}"/*.whl 2>/dev/null | head -1 || true)"
    if [ -z "${wheel}" ]; then
        echo "ERROR: no wheel produced in ${wheel_out}" >&2
        exit 1
    fi
    echo "OK: $(basename "${wheel}")"
    exit 0
fi

command -v rustup >/dev/null || { echo "ERROR: rustup not found on PATH" >&2; exit 1; }

# Idempotently ensure the target std library is present.
rustup target add "${triple}"

echo "Building kerbside-proxy wheel for ${arch} (${triple}), manylinux_2_28, zig linker..."
maturin build \
    --release \
    --target "${triple}" \
    --zig \
    --compatibility manylinux_2_28 \
    --out "${wheel_out}"

# Verify a manylinux wheel for the expected architecture was produced.
# Wheel filenames cannot contain whitespace, so ls -t safely picks the newest.
# shellcheck disable=SC2012
wheel="$(ls -1t "${wheel_out}"/*"${arch}".whl 2>/dev/null | head -1 || true)"
if [ -z "${wheel}" ]; then
    echo "ERROR: no *${arch}.whl produced in ${wheel_out}" >&2
    exit 1
fi
case "$(basename "${wheel}")" in
    *manylinux*"${arch}".whl) ;;
    *)
        echo "ERROR: produced wheel is not manylinux-tagged: $(basename "${wheel}")" >&2
        exit 1
        ;;
esac

echo "OK: $(basename "${wheel}")"
