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
# that, on every run and not only when creating: an existing venv directory or
# interpreter this user does not own is refused rather than used; the directory
# the venv sits in must be owned by this user and not writable by others; no
# directory above it may be writable by others either, since swapping one of
# those swaps the venv; and a venv this script creates is mode 700.
#
# Group-writable is allowed deliberately -- a umask of 002 with a user-private
# group is the Debian default, so ~/.cache is commonly 775 and refusing that
# would reject the default path. So what is left to the operator is a
# QUALITY_VENV under a directory whose group is genuinely shared with other
# people; a group's members cannot be enumerated portably, so the check says
# that rather than pretending to cover it.

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

# Refuse a directory any other local user can write. Read the mode through
# stat and check its exit status: a `find -perm` probe that errors prints
# nothing, which is indistinguishable from a pass. The last octal digit holds
# the other bits, so 2, 3, 6 and 7 are the writable ones.
other_writable() {
    local mode
    if ! mode="$(stat -c '%a' "$1" 2>/dev/null)"; then
        echo "[quality] cannot read the permissions of $1; refusing to run there." >&2
        exit 1
    fi
    case "${mode}" in
        *[2367]) return 0 ;;
        *) return 1 ;;
    esac
}

# Where the venv sits has to be ours on every run, not only on the run that
# creates it: the exec at the bottom runs its python either way. Before
# creation the venv and its parent may not exist yet, so start at the deepest
# ancestor that does.
venv_dir="$(dirname "${QUALITY_VENV}")"
probe="${venv_dir}"
while [ ! -d "${probe}" ] && [ "${probe}" != '/' ] && [ "${probe}" != '.' ]; do
    probe="$(dirname "${probe}")"
done
if [ ! -O "${probe}" ]; then
    echo "[quality] ${probe} is not owned by this user;" >&2
    echo "[quality] refusing to put a venv under it. Set QUALITY_VENV to a path you own." >&2
    exit 1
fi
# Ownership is required of that directory only: /home and / are root-owned on
# every normal system. Writability is checked all the way up, because a
# directory another user can write is one where the whole subtree below it can
# be replaced. A sticky directory such as /tmp is refused too: the sticky bit
# narrows the attack, and this venv is deliberately not under /tmp anyway.
while : ; do
    if other_writable "${probe}"; then
        echo "[quality] ${probe} is writable by any local user;" >&2
        echo "[quality] refusing to put a venv under it. Remove the write bit, or set" >&2
        echo "[quality] QUALITY_VENV to a private path." >&2
        exit 1
    fi
    [ "${probe}" = '/' ] && break
    probe="$(dirname "${probe}")"
done

if [ ! -x "${QUALITY_VENV}/bin/python" ] ||
        ! "${QUALITY_VENV}/bin/python" -c 'import numpy, PIL' 2>/dev/null; then
    # The checks above have already run, on the deepest ancestor that existed,
    # so nothing is created until the location has passed. The venv itself is
    # made mode 700, so bin/python and the modules it imports are not writable
    # even under a umask of 002.
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
