#!/bin/bash
# Build this checkout's kerbside and kerbside-proxy wheels for the sf-e2e lane.
#
# Runs ON the runner, before build-smoke-cluster, because the deploy installs
# them: tools/sf-e2e/deploy-profile.yml.j2 hands both to the kerbside role as
# kerbside_local_wheels, so the lane deploys this pull request's Kerbside
# rather than a release. The profile finds them by name pattern in OUTDIR, so
# OUTDIR is emptied first and the script fails unless it ends up holding
# exactly one wheel of each.
#
# The proxy wheel is the manylinux one the release publishes
# (tools/build-proxy-wheel.sh). The kerbside wheel is built straight from the
# git checkout, which needs full history: setuptools_scm versions it from the
# last v* tag, and only its git file finder includes kerbside.sources and
# kerbside.migrations (kerbside#326).
#
# The build tools go in a venv of their own which is put on PATH here only.
# Later steps in the job run the cluster tooling with the runner's python3,
# which this venv must not shadow.
#
# PREREQUISITES: a Rust toolchain with rustup (dtolnay/rust-toolchain), and
# build-essential and pkg-config for the proxy's native dependencies.
#
# Usage: build-wheels.sh OUTDIR

set -euo pipefail

OUTDIR="${1:?Usage: $0 OUTDIR}"

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
venv="${RUNNER_TEMP:-/tmp}/sf-e2e-wheel-venv"

echo "[sf-e2e] Creating the wheel build venv at ${venv}"
python3 -m venv "${venv}"
"${venv}/bin/pip" install --quiet --upgrade \
    pip build maturin ziglang setuptools_scm
export PATH="${venv}/bin:${PATH}"

rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}"

# The kerbside wheel first: build-proxy-wheel.sh stamps the proxy crate's
# pyproject.toml while it runs, and the kerbside wheel's version should not
# see that as a dirty tree.
echo "[sf-e2e] Building the kerbside wheel"
python3 -m build --wheel --outdir "${OUTDIR}" "${repo_root}"

echo "[sf-e2e] Building the kerbside-proxy wheel"
WHEEL_OUT="${OUTDIR}" "${repo_root}/tools/build-proxy-wheel.sh" "$(uname -m)"

for pattern in 'kerbside-*.whl' 'kerbside_proxy-*.whl'; do
    count="$(find "${OUTDIR}" -maxdepth 1 -name "${pattern}" | wc -l)"
    if [ "${count}" -ne 1 ]; then
        echo "ERROR: ${OUTDIR} holds ${count} ${pattern}, expected 1" >&2
        exit 1
    fi
done

echo "[sf-e2e] Built:"
ls -1 "${OUTDIR}"
