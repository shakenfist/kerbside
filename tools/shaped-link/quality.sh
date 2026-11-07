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
# the interpreter and have it run as whoever runs the rig. Two checks enforce
# that: an existing venv directory or interpreter this user does not own is
# refused rather than used, and a venv is created mode 700, only under a parent
# directory this user owns and that no other local user can write. What is left
# to the operator is a QUALITY_VENV pointed by hand at a path whose group is
# shared with other people, which the script cannot check portably and says so
# at the check rather than pretending to.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Fail with this tool's own message rather than "HOME: unbound variable" under
# set -u, which is what a container shell, a cron or systemd unit, or env -i
# would otherwise get.
if [ -z "${QUALITY_VENV:-}" ] && [ -z "${XDG_CACHE_HOME:-}" ] && [ -z "${HOME:-}" ]; then
    echo "[quality] none of QUALITY_VENV, XDG_CACHE_HOME or HOME is set." >&2
    echo "[quality] Set QUALITY_VENV to a path you own." >&2
    exit 1
fi
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
    # The venv is about to be created and then executed, so the directory it
    # lands in has to be ours: -O rules out another owner, and refusing an
    # other-writable parent rules out the /tmp-shaped case, where any local
    # user could swap the whole venv directory between its creation and the
    # exec below. The venv itself is then made mode 700, so bin/python and the
    # modules it imports are not writable even under a umask of 002.
    #
    # Group-writable is deliberately *not* refused: a umask of 002 with a
    # user-private group is the Debian default, so ~/.cache is commonly 775
    # and refusing that would reject the default path. A parent whose group is
    # shared with other people is therefore the one case left to the operator;
    # there is no portable way to enumerate a group's members (getent omits
    # users whose primary group it is), so this says so rather than pretending
    # to check it.
    venv_parent="$(dirname "${QUALITY_VENV}")"
    mkdir -p "${venv_parent}"
    if [ ! -O "${venv_parent}" ]; then
        echo "[quality] ${venv_parent} is not owned by this user;" >&2
        echo "[quality] refusing to create a venv there. Set QUALITY_VENV to a path you own." >&2
        exit 1
    fi
    if [ -n "$(find "${venv_parent}" -maxdepth 0 -perm /002)" ]; then
        echo "[quality] ${venv_parent} is writable by any local user;" >&2
        echo "[quality] refusing to create a venv there. Remove the write bit, or set" >&2
        echo "[quality] QUALITY_VENV to a private path." >&2
        exit 1
    fi
    echo "[quality] creating ${QUALITY_VENV}" >&2
    mkdir -p "${QUALITY_VENV}"
    chmod 700 "${QUALITY_VENV}"
    python3 -m venv "${QUALITY_VENV}"
    "${QUALITY_VENV}/bin/pip" install --quiet --disable-pip-version-check numpy Pillow
fi

if [ "${1:-}" = 'test' ]; then
    cd "${SCRIPT_DIR}"
    exec "${QUALITY_VENV}/bin/python" -B -m unittest -v test_quality
fi
exec "${QUALITY_VENV}/bin/python" "${SCRIPT_DIR}/quality.py" "$@"
