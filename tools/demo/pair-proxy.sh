#!/bin/bash
# Pick the kerbside-proxy the demo lane's image installs.
#
# Normally that is the newest dev wheel published from develop by
# dev-proxy-wheel.yml, which a KERBSIDE_SOURCE=/src build resolves on its
# own through pyproject.toml's dev-inclusive floor. That is only right
# while this checkout's kerbside/rpc/kerbside.proto is the one that wheel
# was built from. When it is not -- a pull request changing the proto, or
# develop in the window between such a merge and the dev wheel it
# triggers -- the daemon's contract check refuses the published binary
# and the lane goes red for a reason that is not the demo's.
#
# So this asks the published wheel directly: download it, run its binary
# with --contract-hash, and compare that with the sha256 of this
# checkout's proto, which is exactly what the daemon's check_contract()
# compares. If they match, nothing is built and the image installs the
# published wheel as before. If they differ, or the published wheel
# cannot be fetched or asked, the proxy is built from this checkout with
# tools/build-proxy-wheel.sh --native and the image is pointed at it via
# KERBSIDE_PROXY. Building is the safe answer to "cannot tell", because it
# costs minutes where the wrong guess costs a red lane.
#
# The native wheel is built on the runner and installed in the image,
# which is only sound while both share a glibc: the runner is debian-13
# and python:3.13-slim is trixie. If either moves, build the manylinux
# wheel instead (tools/build-proxy-wheel.sh x86_64, which needs rustup and
# ziglang).
#
# Needs cargo on PATH and full git history (the wheel's dev version comes
# from setuptools_scm). Installs maturin and setuptools_scm into a venv of
# its own. In CI it writes KERBSIDE_PROXY to $GITHUB_ENV for
# tools/demo/lane-up.sh; run by hand, it prints the export to use.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Inside the build context (the repository root), because the image's pip
# step reads it through the /src bind mount, and outside dist/, which
# .dockerignore excludes. .gitignore excludes it instead.
WHEEL_DIR="demo/.proxy-wheel"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

python3 -m venv "${WORK}/venv"
PIP="${WORK}/venv/bin/pip"
"${PIP}" install --quiet --upgrade pip

expected="$(sha256sum "${REPO_ROOT}/kerbside/rpc/kerbside.proto" | cut -d' ' -f1)"
echo "[pair-proxy] This checkout's contract hash: ${expected}"

# --pre because the image's resolver allows pre-releases too: the floor in
# pyproject.toml names a .dev0 version, which makes every dev wheel
# eligible, so the newest version overall is what the image would get.
published=''
if "${PIP}" download --quiet --pre --no-deps --only-binary :all: \
        --dest "${WORK}/published" kerbside-proxy; then
    wheel="$(find "${WORK}/published" -name 'kerbside_proxy-*.whl' | head -1)"
    echo "[pair-proxy] Published wheel: $(basename "${wheel}")"
    "${WORK}/venv/bin/python" -m zipfile -e "${wheel}" "${WORK}/unpacked"
    bin="$(find "${WORK}/unpacked" -path '*.data/scripts/kerbside-proxy' | head -1)"
    if [ -n "${bin}" ]; then
        chmod +x "${bin}"
        published="$("${bin}" --contract-hash 2>/dev/null || true)"
    fi
fi
echo "[pair-proxy] Published wheel's contract hash: ${published:-unknown}"

if [ "${published}" = "${expected}" ]; then
    echo "[pair-proxy] They match: the image installs the published wheel"
    exit 0
fi

echo "[pair-proxy] They differ: building the proxy from this checkout"
"${PIP}" install --quiet maturin setuptools_scm
rm -rf "${REPO_ROOT:?}/${WHEEL_DIR}"
PATH="${WORK}/venv/bin:${PATH}" WHEEL_OUT="${REPO_ROOT}/${WHEEL_DIR}" \
    "${REPO_ROOT}/tools/build-proxy-wheel.sh" --native

built="$(find "${REPO_ROOT}/${WHEEL_DIR}" -name 'kerbside_proxy-*.whl' | head -1)"
KERBSIDE_PROXY="/src/${WHEEL_DIR}/$(basename "${built}")"
echo "[pair-proxy] The image installs ${KERBSIDE_PROXY}"

if [ -n "${GITHUB_ENV:-}" ]; then
    echo "KERBSIDE_PROXY=${KERBSIDE_PROXY}" >> "${GITHUB_ENV}"
else
    echo "export KERBSIDE_PROXY=${KERBSIDE_PROXY}"
fi
