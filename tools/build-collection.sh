#!/bin/bash
#
# build-collection.sh -- build the shakenfist.kerbside ansible collection
# for a release.
#
# Usage: tools/build-collection.sh VERSION [OUTPUT_DIR]
#
# VERSION is the release version without the leading v, the same string
# the Python packages are built with (SETUPTOOLS_SCM_PRETEND_VERSION in
# the release workflow): X.Y.Z, or a PEP 440 pre-release such as
# 0.8.0rc1. Ansible Galaxy accepts only a semantic version, so the
# collection's own version spells a pre-release the semantic way
# (0.8.0-rc1), while the pin on the Python package keeps PEP 440's
# spelling, which pip needs. Anything else is refused. OUTPUT_DIR
# defaults to dist-collection/ in the repository root.
#
# The collection is copied to a temporary directory and four values are
# stamped into the copy, so that collection X.Y.Z installs Kerbside X.Y.Z
# by default, documents that default, and reports its own version:
#
#   galaxy.yml                            version: X.Y.Z
#   roles/kerbside/defaults/main.yml      kerbside_package: "kerbside==X.Y.Z"
#   roles/kerbside/meta/argument_specs.yml  the same default, documented
#   roles/kerbside/vars/main.yml          kerbside_collection_version: "X.Y.Z"
#
# The checkout itself is never modified. Rewriting tracked files in place
# leaves the working tree dirty, and a dirty tree gives every later
# setuptools_scm version a local suffix that PyPI rejects, so the release
# build of the wheel which follows would fail.
#
# Needs ansible-galaxy on PATH.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] \
    || fail "usage: $0 VERSION [OUTPUT_DIR]"
VERSION="$1"
OUTPUT_DIR="${2:-${REPO_ROOT}/dist-collection}"

RELEASE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)((a|b|rc)(0|[1-9][0-9]*))?$'
[[ "${VERSION}" =~ ${RELEASE} ]] \
    || fail "'${VERSION}' is neither X.Y.Z nor a PEP 440 pre-release such as X.Y.Zrc1"
# The collection's semantic version: 0.8.0rc1 becomes 0.8.0-rc1.
if [ -n "${BASH_REMATCH[4]}" ]; then
    COLLECTION_VERSION="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}-${BASH_REMATCH[4]}"
else
    COLLECTION_VERSION="${VERSION}"
fi
command -v ansible-galaxy > /dev/null || fail 'ansible-galaxy not found on PATH'

WORK="$(mktemp -d "${TMPDIR:-/tmp}/build-collection.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

STAGE="${WORK}/ansible"
cp -a "${REPO_ROOT}/ansible" "${STAGE}"

# stamp FILE PATTERN REPLACEMENT: replace the one line matching PATTERN,
# and fail if it did not match exactly one line, so that a reworded
# committed file cannot silently release unstamped.
stamp() {
    local file="$1" pattern="$2" replacement="$3" count
    count="$(grep -c -E "${pattern}" "${file}" || true)"
    [ "${count}" = 1 ] \
        || fail "expected one line matching '${pattern}' in ${file#"${WORK}"/}, found ${count}"
    sed -i -E "s|${pattern}.*|${replacement}|" "${file}"
}

stamp "${STAGE}/galaxy.yml" '^version:' "version: ${COLLECTION_VERSION}"
stamp "${STAGE}/roles/kerbside/defaults/main.yml" '^kerbside_package:' \
    "kerbside_package: \"kerbside==${VERSION}\""
stamp "${STAGE}/roles/kerbside/meta/argument_specs.yml" \
    '^( +)default: "kerbside>=' \
    "\\1default: \"kerbside==${VERSION}\""
stamp "${STAGE}/roles/kerbside/vars/main.yml" '^kerbside_collection_version:' \
    "kerbside_collection_version: \"${COLLECTION_VERSION}\""

mkdir -p "${OUTPUT_DIR}"
ansible-galaxy collection build "${STAGE}" --output-path "${OUTPUT_DIR}" --force
