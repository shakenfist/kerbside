#!/bin/bash
# Run quality.py, or its tests, in a venv that holds numpy and Pillow.
#
# Usage: quality.sh cases --reference REF.png WORKDIR...
#        quality.sh pair --reference REF.png IMAGE.png [--exclude L,T,R,B]...
#        quality.sh test
#
# The venv lives at QUALITY_VENV (default
# ${XDG_CACHE_HOME:-$HOME/.cache}/kerbside/shaped-link-venv). It is created on
# first use and reused after that; it holds nothing but numpy and Pillow, so
# delete it whenever you like and the next run makes it again. It stays out of
# WORKDIR because summarise.py reads every directory there as a link profile,
# and out of the repository's own environments because nothing else in kerbside
# needs numpy.
#
# It is deliberately not under /tmp. This script executes the venv's python, so
# a fixed path in a world-writable directory lets any other local user plant
# the interpreter and have it run as whoever runs the rig. For the same reason
# an existing venv that this user does not own is refused rather than used,
# which also covers a QUALITY_VENV pointed at a shared path by hand.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QUALITY_VENV="${QUALITY_VENV:-${XDG_CACHE_HOME:-${HOME}/.cache}/kerbside/shaped-link-venv}"

# Refuse a venv this user does not own, directory or interpreter: the lines
# below execute it.
for path in "${QUALITY_VENV}" "${QUALITY_VENV}/bin/python"; do
    if [ -e "${path}" ] && [ ! -O "${path}" ]; then
        echo "[quality] ${path} is not owned by this user; refusing to use it." >&2
        echo "[quality] Remove it, or set QUALITY_VENV to a path you own." >&2
        exit 1
    fi
done

if [ ! -x "${QUALITY_VENV}/bin/python" ] ||
        ! "${QUALITY_VENV}/bin/python" -c 'import numpy, PIL' 2>/dev/null; then
    echo "[quality] creating ${QUALITY_VENV}" >&2
    mkdir -p "$(dirname "${QUALITY_VENV}")"
    python3 -m venv "${QUALITY_VENV}"
    "${QUALITY_VENV}/bin/pip" install --quiet --disable-pip-version-check numpy Pillow
fi

if [ "${1:-}" = 'test' ]; then
    cd "${SCRIPT_DIR}"
    exec "${QUALITY_VENV}/bin/python" -B -m unittest -v test_quality
fi
exec "${QUALITY_VENV}/bin/python" "${SCRIPT_DIR}/quality.py" "$@"
