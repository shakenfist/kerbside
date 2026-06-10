#!/bin/bash
# Rebuild the Uncalibrated Sextant qcow2 fixture from source.
#
# Usage:
#   ./rebuild-sextant-qcow2.sh [--sextant-repo PATH] [--kerbside-root PATH]
#
# Defaults:
#   --sextant-repo  /srv/kasm_profiles/mikal/vscode/src/shakenfist/uncalibrated-sextant
#   --kerbside-root auto-detected from this script's location (two dirs up)
#
# This script is NOT called by CI. It is a developer convenience for
# refreshing tests/fixtures/uncalibrated-sextant.qcow2 when Sextant
# changes. After running it, review the diff and commit if the image
# has changed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults
SEXTANT_REPO='/srv/kasm_profiles/mikal/vscode/src/shakenfist/uncalibrated-sextant'
KERBSIDE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sextant-repo)
            SEXTANT_REPO="$2"
            shift 2
            ;;
        --kerbside-root)
            KERBSIDE_ROOT="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--sextant-repo PATH] [--kerbside-root PATH]" >&2
            exit 1
            ;;
    esac
done

DEST="${KERBSIDE_ROOT}/tests/fixtures/uncalibrated-sextant.qcow2"

# Validate the sextant repo
if [[ ! -d "${SEXTANT_REPO}" ]]; then
    echo "ERROR: sextant repo not found at '${SEXTANT_REPO}'" >&2
    echo "Pass --sextant-repo PATH to override." >&2
    exit 1
fi

if [[ ! -f "${SEXTANT_REPO}/Makefile" ]]; then
    echo "ERROR: '${SEXTANT_REPO}' has no Makefile; does not look like sextant." >&2
    exit 1
fi

if [[ ! -f "${SEXTANT_REPO}/Cargo.toml" ]]; then
    echo "ERROR: '${SEXTANT_REPO}' has no Cargo.toml; does not look like sextant." >&2
    exit 1
fi

echo "==> sextant repo : ${SEXTANT_REPO}"
echo "==> kerbside root: ${KERBSIDE_ROOT}"
echo "==> destination  : ${DEST}"
echo

# Build
cd "${SEXTANT_REPO}"
echo "==> Running: make release"
make release

BUILT="${SEXTANT_REPO}/dist/uncalibrated-sextant.qcow2"
if [[ ! -f "${BUILT}" ]]; then
    echo "ERROR: make release completed but '${BUILT}' not found." >&2
    exit 1
fi

# Copy to fixture location
cp "${BUILT}" "${DEST}"

# Report
CHECKSUM="$(sha256sum "${DEST}" | awk '{print $1}')"
echo
echo "==> SHA256: ${CHECKSUM}  ${DEST}"
echo
echo "Refreshed tests/fixtures/uncalibrated-sextant.qcow2."
echo "Run 'git diff --stat' to see the new size, then commit if it changed."
