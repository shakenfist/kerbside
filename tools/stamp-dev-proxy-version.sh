#!/bin/bash
#
# Stamp a PEP 440 DEV version into the `kerbside-proxy` maturin "bin" wheel
# so that dev builds published from the develop branch carry a version that
# matches the `kerbside` dev wheel's own setuptools_scm-derived version.
#
# `rust/kerbside-proxy/pyproject.toml` normally declares
# `dynamic = ["version"]`, which tells maturin to read the wheel version out
# of `rust/kerbside-proxy/Cargo.toml` ([package] version). That works for
# release builds, but Cargo requires a valid semver, and a setuptools_scm dev
# version such as `0.4.1.dev159+g1234abcd` is not valid semver -- it cannot
# be stamped into Cargo.toml. Instead, this script replaces the
# `dynamic = ["version"]` line with a static `version = "X.Y.Z.devN"` line,
# which maturin prefers over the Cargo-derived version when both are
# present.
#
# The version is derived the same way the `kerbside` package derives its
# own: `python3 -m setuptools_scm`, run at the repo root. This requires the
# setuptools_scm module to be importable and requires the full git history
# (including tags) to be present -- a shallow clone will not produce a
# usable version. The PEP 440 local segment (the `+g1234abcd` part) is
# stripped before validation and stamping, because PyPI rejects local
# versions.
#
# Usage:
#   tools/stamp-dev-proxy-version.sh 0.4.1.dev159   # explicit version
#   tools/stamp-dev-proxy-version.sh                # derive via
#                                                    # setuptools_scm
#
# This script is meant to run at DEV-RELEASE time from the develop branch,
# so it requires a setuptools_scm dev version (MAJOR.MINOR.PATCH.devN); a
# final release version (e.g. 0.4.1) is rejected because that is what
# tools/stamp-proxy-version.sh is for. The two scripts are complementary and
# each refuses the other's input.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
py_toml="${repo_root}/rust/kerbside-proxy/pyproject.toml"

version="${1:-}"
if [ -z "${version}" ]; then
    # Derive from the working tree the same way the kerbside wheel does.
    # Requires the setuptools_scm module (a build dependency) and full git
    # history.
    version="$(cd "${repo_root}" && python3 -m setuptools_scm 2>/dev/null)"
fi

if [ -z "${version}" ]; then
    echo "ERROR: no version supplied and setuptools_scm produced none." >&2
    echo "Pass the dev version explicitly, e.g. $0 0.4.1.dev159" >&2
    exit 1
fi

# Strip the PEP 440 local segment (e.g. +g1234abcd), if present. PyPI
# rejects local versions, so only the public version is ever stamped.
version="${version%%+*}"

# Require a setuptools_scm dev version (MAJOR.MINOR.PATCH.devN). This is a
# dev-release-time tool; a final release version is not what it stamps.
if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.dev[0-9]+$ ]]; then
    echo "ERROR: '${version}' is not a dev version (MAJOR.MINOR.PATCH.devN)." >&2
    echo "This tool stamps dev builds only; refusing to publish a release version." >&2
    echo "For a final release version, use tools/stamp-proxy-version.sh instead." >&2
    exit 1
fi

if [ ! -f "${py_toml}" ]; then
    echo "ERROR: expected file not found: ${py_toml}" >&2
    exit 1
fi

# Anchor to the exact `dynamic = ["version"]` line; it is the only `dynamic`
# line in the file. If it is absent, the tree has already been stamped --
# fail loudly rather than double-stamp.
if ! grep -Fxq 'dynamic = ["version"]' "${py_toml}"; then
    echo "ERROR: no 'dynamic = [\"version\"]' line found in ${py_toml}" >&2
    echo "The file appears already stamped. Restore it with:" >&2
    echo "  git checkout -- rust/kerbside-proxy/pyproject.toml" >&2
    exit 1
fi
sed -i "s/^dynamic = \[\"version\"\]\$/version = \"${version}\"/" "${py_toml}"

echo "Stamped dev version ${version} into:"
echo "  ${py_toml} (version, replacing dynamic = [\"version\"])"
