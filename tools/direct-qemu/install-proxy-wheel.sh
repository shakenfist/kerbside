#!/bin/bash
# Build the kerbside-proxy wheel natively and install it into a venv, so the
# daemon's find_proxy_bin() resolves it via shutil.which('kerbside-proxy') on
# PATH -- the real production install path, exercised in the direct-qemu
# Rust lane (and locally).
#
# Usage:
#   tools/direct-qemu/install-proxy-wheel.sh --venv /tmp/kerbside-venv
#   tools/direct-qemu/install-proxy-wheel.sh          # use pip/python3 on PATH
#
# Requires `maturin` on PATH plus, on an unstamped tree, `setuptools_scm`
# importable by python3 and FULL git history -- build-proxy-wheel.sh
# dev-stamps the wheel version from setuptools_scm so it satisfies
# kerbside's committed dependency floor, and a shallow clone cannot count
# commits since the last v* tag (see the dev-stamp block in
# tools/build-proxy-wheel.sh). A native build still needs only a host
# cargo, not rustup/ziglang. Reuses the tools/build-proxy-wheel.sh
# --native fast path so wheel-building logic lives in one place.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VENV=''
while [ $# -gt 0 ]; do
    case "$1" in
        --venv) VENV="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -n "${VENV}" ]; then
    PIP="${VENV}/bin/pip"
    PYTHON="${VENV}/bin/python"
    BIN_DIR="${VENV}/bin"
    for exe in "${PIP}" "${PYTHON}"; do
        if [ ! -x "${exe}" ]; then
            echo "ERROR: ${exe} not found; is --venv ${VENV} a real venv?" >&2
            exit 1
        fi
    done
else
    PIP='pip'
    PYTHON='python3'
    BIN_DIR="$(dirname "$(command -v "${PYTHON}")")"
fi

command -v maturin >/dev/null || { echo "ERROR: maturin not found on PATH" >&2; exit 1; }

# ── Build the native wheel ────────────────────────────────────────────────────

WHEEL_OUT="${WHEEL_OUT:-${REPO_ROOT}/dist/proxy-wheels}"
export WHEEL_OUT
echo "[install-proxy-wheel] Building native kerbside-proxy wheel into ${WHEEL_OUT}"
"${REPO_ROOT}/tools/build-proxy-wheel.sh" --native

# Wheel filenames cannot contain whitespace, so ls -t safely picks the newest.
# shellcheck disable=SC2012
WHEEL="$(ls -1t "${WHEEL_OUT}"/kerbside_proxy-*.whl 2>/dev/null | head -1 || true)"
if [ -z "${WHEEL}" ]; then
    echo "ERROR: no kerbside_proxy wheel produced in ${WHEEL_OUT}" >&2
    exit 1
fi

# ── Install and verify PATH resolution ────────────────────────────────────────

echo "[install-proxy-wheel] Installing $(basename "${WHEEL}") into ${BIN_DIR%/bin}"
"${PIP}" install --quiet --force-reinstall "${WHEEL}"

# Assert find_proxy_bin()'s shutil.which leg resolves the installed binary
# with the venv's bin on PATH (the production resolution path).
RESOLVED="$(PATH="${BIN_DIR}:${PATH}" "${PYTHON}" -c \
    "import shutil; print(shutil.which('kerbside-proxy') or '')")"
if [ -z "${RESOLVED}" ]; then
    echo "ERROR: kerbside-proxy not on PATH after install (expected in ${BIN_DIR})" >&2
    exit 1
fi
echo "[install-proxy-wheel] OK: kerbside-proxy resolves to ${RESOLVED}"
