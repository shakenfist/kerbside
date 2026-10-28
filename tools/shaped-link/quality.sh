#!/bin/bash
# Run quality.py, or its tests, in a venv that holds numpy and Pillow.
#
# Usage: quality.sh cases --reference REF.png WORKDIR...
#        quality.sh pair --reference REF.png IMAGE.png [--exclude L,T,R,B]...
#        quality.sh test
#
# The venv lives at QUALITY_VENV (default ${TMPDIR:-/tmp}/kerbside-shaped-link-venv).
# It is created on first use and reused after that; it holds nothing but
# numpy and Pillow, so delete it whenever you like and the next run makes it
# again. It stays out of WORKDIR because summarise.py reads every directory
# there as a link profile, and out of the repository's own environments
# because nothing else in kerbside needs numpy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QUALITY_VENV="${QUALITY_VENV:-${TMPDIR:-/tmp}/kerbside-shaped-link-venv}"

if [ ! -x "${QUALITY_VENV}/bin/python" ] ||
        ! "${QUALITY_VENV}/bin/python" -c 'import numpy, PIL' 2>/dev/null; then
    echo "[quality] creating ${QUALITY_VENV}" >&2
    python3 -m venv "${QUALITY_VENV}"
    "${QUALITY_VENV}/bin/pip" install --quiet --disable-pip-version-check numpy Pillow
fi

if [ "${1:-}" = 'test' ]; then
    cd "${SCRIPT_DIR}"
    exec "${QUALITY_VENV}/bin/python" -B -m unittest -v test_quality
fi
exec "${QUALITY_VENV}/bin/python" "${SCRIPT_DIR}/quality.py" "$@"
