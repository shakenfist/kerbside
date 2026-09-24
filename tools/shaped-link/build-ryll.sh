#!/bin/bash
# Build the ryll client used by the shaped-link latency rig.
#
# Usage: build-ryll.sh OUTDIR
#
# Clones ryll (RYLL_SRC, a local checkout or a git URL; RYLL_REF, default
# the source's HEAD) into OUTDIR/ryll, applies ryll-surface-drawn-rect.patch
# and builds a release binary in ryll's own ryll-dev Docker image, never
# with a host Rust toolchain. The binary lands at
# OUTDIR/ryll/target/release/ryll.
#
# The patch adds a `rect` field ([left, top, right, bottom]) to the
# control socket's `surface_drawn` event. keydraw-latency.py needs it to
# tell the guest's key-box draw apart from the screen activity's draws.
# It is an additive field, so it is a candidate for ryll's control socket
# protocol proper; until it lands there, it lives here.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTDIR="${1:?usage: build-ryll.sh OUTDIR}"
RYLL_SRC="${RYLL_SRC:-${REPO_ROOT}/../ryll}"
if [ ! -d "${RYLL_SRC}" ]; then
    RYLL_SRC='https://github.com/shakenfist/ryll.git'
fi
RYLL_REF="${RYLL_REF:-HEAD}"

mkdir -p "${OUTDIR}"
SRC="${OUTDIR}/ryll"
if [ ! -d "${SRC}/.git" ]; then
    git clone --quiet "${RYLL_SRC}" "${SRC}"
fi
git -C "${SRC}" checkout --quiet --force "${RYLL_REF}"
git -C "${SRC}" apply "${SCRIPT_DIR}/ryll-surface-drawn-rect.patch"
echo "[build-ryll] ryll $(git -C "${SRC}" rev-parse --short HEAD) + surface_drawn rect patch"

# ryll's Makefile builds its dev image and pre-fetches crates (the only
# networked step); the compile itself then runs offline, as ryll's own
# `make release` does.
make -C "${SRC}" fetch
docker run --rm --network none \
    -v "${SRC}":/workspace -w /workspace \
    -u "$(id -u):$(id -g)" -e HOME=/build \
    -v "${SRC}/.cargo-cache/registry":/build/.cargo/registry:ro \
    -v "${SRC}/.cargo-cache/git":/build/.cargo/git:ro \
    ryll-dev cargo build --release --frozen -p ryll --no-default-features
echo "[build-ryll] built ${SRC}/target/release/ryll"
