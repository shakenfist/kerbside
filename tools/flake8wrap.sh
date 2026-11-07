#!/bin/sh
#
# A simple wrapper around flake8 which makes it possible
# to ask it to only verify files changed in the current
# git HEAD patch, or in a set of git ranges.
#
# Intended to be invoked via tox:
#
#   tox -eflake8 -- -HEAD
#   tox -eflake8 -- -RANGE <git-range> [<git-range> ...]
#
# tools/audit/wave1.sh uses the second form to point the lint gate at
# the ranges it is auditing. -HEAD remains the default, and the bare
# `tox -eflake8` CI gate is unchanged.
#
# Originally from the OpenStack project.

FLAKE_COMMAND="flake8 --max-line-length=120"

# lint_files <description> <file...>
#
# Drops files the change deleted, then lints what is left. Shared by
# both selection modes so that neither can grow its own version of the
# vanished-file handling.
lint_files() {
    description="$1"
    shift

    filtered_files=""
    for file in "$@"; do
        if [ -e "$file" ]; then
            filtered_files="${filtered_files} ${file}"
        else
            echo "$file does not exist in the end state, skipping."
        fi
    done

    # Every candidate can vanish, if the change deleted python files
    # rather than editing them. Stop here rather than falling through:
    # the command below treats an empty file list as "no arguments",
    # and flake8 with no arguments walks the whole tree -- including
    # the generated _pb2 stubs the caller's grep exists to exclude.
    if [ -z "${filtered_files}" ]; then
        echo "No python files remain in the end state for ${description}."
        exit 0
    fi

    echo "Running flake8 on ${filtered_files}"
    # shellcheck disable=SC2086
    diff -u --from-file /dev/null ${filtered_files} | $FLAKE_COMMAND ${filtered_files}
}

if test "$1" = "-HEAD" ; then
    shift
    files=$(git diff --name-only HEAD~1 | grep -v _pb2 | grep -E ".py$")
    if [ -z "${files}" ]; then
        echo "No python files in change."
        exit 0
    fi

    # shellcheck disable=SC2086  # a git path list carries no whitespace
    lint_files "HEAD~1..HEAD" ${files}
elif test "$1" = "-RANGE" ; then
    shift
    if [ "$#" -eq 0 ]; then
        echo "flake8wrap.sh: -RANGE needs at least one git range." >&2
        exit 1
    fi

    # Resolve every range before diffing any of them. An unresolvable
    # range makes `git diff` write to stderr and produce nothing, and
    # inside the command substitution below its exit status is lost, so
    # the file list comes back empty and the gate reports a clean pass
    # over a range it never read. That is the defect this mode exists to
    # fix, so it must not reappear here.
    for range in "$@"; do
        if ! git rev-parse --verify "${range%%..*}" >/dev/null 2>&1 \
                || ! git rev-parse --verify "${range##*..}" >/dev/null 2>&1; then
            echo "flake8wrap.sh: range '${range}' does not resolve." >&2
            exit 1
        fi
    done

    files=$(for range in "$@"; do
        git diff --name-only "${range}"
    done | sort -u | grep -v _pb2 | grep -E ".py$")

    # Name the ranges rather than saying "no python files in change":
    # the point of this mode is that the reader can tell what was read.
    if [ -z "${files}" ]; then
        echo "No python files in $*."
        exit 0
    fi

    # shellcheck disable=SC2086  # a git path list carries no whitespace
    lint_files "$*" ${files}
else
    echo "Running flake8 on all files"
    exec $FLAKE_COMMAND "$@"
fi
