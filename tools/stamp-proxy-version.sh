#!/bin/bash
#
# Stamp a single release version into both halves of the lockstep pair so
# that `kerbside` and `kerbside-proxy` are published from one `v*` tag with
# matching versions and an exact pin between them.
#
# The `v*` git tag is the SINGLE SOURCE OF TRUTH. `kerbside` derives its
# version from that tag via setuptools_scm; this script propagates the same
# version to:
#
#   1. rust/kerbside-proxy/Cargo.toml   -- [package] version = "X.Y.Z"
#      (maturin reads the wheel version from here via `dynamic = ["version"]`)
#   2. pyproject.toml                   -- the "kerbside-proxy==X.Y.Z" pin,
#      INSERTED into the `kerbside` dependency list immediately before the
#      `# KERBSIDE_PROXY_PIN` marker (or its version replaced if already
#      present)
#
# so that `pip install kerbside==X.Y.Z` transitively installs
# `kerbside-proxy==X.Y.Z` and the gRPC contract matches by construction.
#
# COMMITTED-PIN POLICY: the source tree commits a dev-inclusive floor,
# `"kerbside-proxy>=X.Y.Z.dev0"`, so that a plain `pip install` of a git
# checkout resolves the newest kerbside-proxy wheel on PyPI -- released or
# rolling dev -- as published by dev-proxy-wheel.yml. This script TIGHTENS
# that line to the exact `kerbside-proxy==X.Y.Z` lockstep pin at release
# time, before the kerbside wheel is built.
#
# Usage:
#   tools/stamp-proxy-version.sh 0.2.6        # explicit version
#   tools/stamp-proxy-version.sh              # derive from the tag via
#                                             # setuptools_scm
#
# This script is meant to run at RELEASE time on a clean `v*` tag, so it
# requires a final release version (MAJOR.MINOR.PATCH); a setuptools_scm dev
# version (e.g. 0.2.6.dev62+g...) is rejected because it is not a valid Cargo
# semver and must not be published.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cargo_toml="${repo_root}/rust/kerbside-proxy/Cargo.toml"
py_toml="${repo_root}/pyproject.toml"

version="${1:-}"
if [ -z "${version}" ]; then
    # Derive from the tag the same way the kerbside wheel does. Requires the
    # setuptools_scm module (a build dependency).
    version="$( { cd "${repo_root}" && python3 -m setuptools_scm; } 2>/dev/null || true)"
fi

if [ -z "${version}" ]; then
    echo "ERROR: no version supplied and setuptools_scm produced none." >&2
    echo "Pass the release version explicitly, e.g. $0 0.2.6" >&2
    exit 1
fi

# Reject anything that is not a final MAJOR.MINOR.PATCH release. This is a
# release-time tool; a dev/local version is not publishable and is not a
# valid Cargo semver.
if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: '${version}' is not a final release version (MAJOR.MINOR.PATCH)." >&2
    echo "This tool stamps release builds only; refusing to publish a dev version." >&2
    exit 1
fi

for f in "${cargo_toml}" "${py_toml}"; do
    if [ ! -f "${f}" ]; then
        echo "ERROR: expected file not found: ${f}" >&2
        exit 1
    fi
done

# 1. Cargo.toml [package] version. Dependency versions are written as
#    `key = { version = ... }`, so anchoring to a line that STARTS with
#    `version = "` matches only the [package] version line.
if ! grep -Eq '^version = "[^"]*"$' "${cargo_toml}"; then
    echo "ERROR: no '[package] version = \"...\"' line found in ${cargo_toml}" >&2
    exit 1
fi
sed -i -E "s/^version = \"[^\"]*\"$/version = \"${version}\"/" "${cargo_toml}"

# 2. The kerbside-proxy requirement in the kerbside dependency list. The
#    normal case is the committed dev-inclusive floor (`>=X.Y.Z.dev0`) or an
#    already-stamped exact pin (`==X.Y.Z`) from a prior run of this script;
#    either way, rewrite the whole quoted requirement -- whatever specifier
#    operator it uses -- to the exact `==${version}` pin, leaving the
#    trailing license comment untouched. If no kerbside-proxy requirement is
#    present at all (a hypothetical old tree), fall back to inserting one
#    immediately before the `# KERBSIDE_PROXY_PIN` marker, mirroring the
#    `# END_OF_INDIRECT_DEPS` insertion pattern the pin-indirect-dependencies
#    workflow uses.
if grep -Eq '"kerbside-proxy[=><~!][^"]*"' "${py_toml}"; then
    sed -i -E "s/\"kerbside-proxy[=><~!][^\"]*\"/\"kerbside-proxy==${version}\"/" "${py_toml}"
elif grep -q '# KERBSIDE_PROXY_PIN' "${py_toml}"; then
    sed -i "s|    # KERBSIDE_PROXY_PIN|    \"kerbside-proxy==${version}\",            # apache2\n    # KERBSIDE_PROXY_PIN|" "${py_toml}"
else
    echo "ERROR: neither a kerbside-proxy pin nor the '# KERBSIDE_PROXY_PIN' marker found in ${py_toml}" >&2
    exit 1
fi

echo "Stamped version ${version} into:"
echo "  ${cargo_toml} ([package] version)"
echo "  ${py_toml} (kerbside-proxy pin)"
