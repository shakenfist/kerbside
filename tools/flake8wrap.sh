#!/bin/sh
#
# A simple wrapper around flake8 which makes it possible
# to ask it to only verify files changed in the current
# git HEAD patch.
#
# Intended to be invoked via tox:
#
#   tox -eflake8 -- -HEAD
#
# Originally from the OpenStack project.

FLAKE_COMMAND="flake8 --max-line-length=120"

if test "$1" = "-HEAD" ; then
    shift
    files=$(git diff --name-only HEAD~1 | grep -v _pb2 | grep -E ".py$")
    if [ -z "${files}" ]; then
        echo "No python files in change."
        exit 0
    fi

    filtered_files=""
    for file in $files; do
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
    # the generated _pb2 stubs the grep above exists to exclude.
    if [ -z "${filtered_files}" ]; then
        echo "No python files remain in the end state."
        exit 0
    fi

    echo "Running flake8 on ${filtered_files}"
    # shellcheck disable=SC2086
    diff -u --from-file /dev/null ${filtered_files} | $FLAKE_COMMAND ${filtered_files}
else
    echo "Running flake8 on all files"
    exec $FLAKE_COMMAND "$@"
fi
