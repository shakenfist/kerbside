#!/bin/bash
# Build the andris SPICE server that the shaped-link rig's helper display
# runs in front of qemu's D-Bus display.
#
# Usage: build-andris.sh OUTDIR
#
# Clones andris (ANDRIS_SRC, a local checkout or a git URL; ANDRIS_REF, see
# below) into OUTDIR/andris and builds a release binary with andris's qemu
# platform (`make release FEATURES=qemu`), in andris's own andris-dev
# Docker image, never with a host Rust toolchain. The binary lands at
# OUTDIR/andris/target/release/andris; run-matrix.sh takes it as
# ANDRIS_BIN.
#
# ANDRIS_SRC defaults to a sibling checkout (../andris next to this
# repository) when there is one, and to andris upstream otherwise. An
# explicit ANDRIS_SRC is used as is, so a typo fails at the clone instead
# of quietly building upstream.
#
# ANDRIS_REF defaults to a fixed commit rather than the source's HEAD, so
# every run measures the same helper and results stay comparable. The
# qemu platform is behind andris's non-default `qemu` cargo feature; the
# pinned commit must have it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTDIR="${1:?usage: build-andris.sh OUTDIR}"
if [ -z "${ANDRIS_SRC:-}" ]; then
    ANDRIS_SRC="${REPO_ROOT}/../andris"
    [ -d "${ANDRIS_SRC}" ] || ANDRIS_SRC='https://github.com/shakenfist/andris.git'
fi
echo "build-andris.sh: building andris from ${ANDRIS_SRC}"
ANDRIS_REF="${ANDRIS_REF:-440b782}"

mkdir -p "${OUTDIR}"
SRC="${OUTDIR}/andris"
if [ ! -d "${SRC}/.git" ]; then
    git clone --quiet "${ANDRIS_SRC}" "${SRC}"
fi
# A new ref may postdate the clone, so fetch before checking it out.
git -C "${SRC}" fetch --quiet origin '+refs/heads/*:refs/remotes/origin/*' || true
git -C "${SRC}" checkout --quiet --force "${ANDRIS_REF}"
echo "[build-andris] andris $(git -C "${SRC}" rev-parse --short HEAD)"

# andris's Makefile builds its dev image and pre-fetches crates (the only
# networked step), then compiles offline with the checkout mounted
# read-only.
make -C "${SRC}" release FEATURES=qemu
echo "[build-andris] built ${SRC}/target/release/andris"
