#!/bin/bash
#
# ci-check-ansible-collection.sh -- lint the shakenfist.kerbside
# collection under ansible/, build it, and run galaxy-importer over the
# built tarball.
#
# galaxy-importer is what Ansible Galaxy runs on an upload, so running it
# here finds a metadata error (a missing meta/runtime.yml
# requires_ansible, a role with no README, a malformed galaxy.yml) on the
# pull request that introduces it rather than at release, when the tag
# already exists. Its own ansible-lint pass only warns; the ansible-lint
# run before it, with the collection's configuration, is the one that
# fails.
#
# Both checks always run, so one failure does not hide the other, and the
# script exits non-zero naming each that failed.
#
# The collection is built by tools/build-collection.sh, the release
# build, with a stand-in version, so every pull request exercises the
# stamps a release makes: a reworded line one of them depends on fails
# here, not after a tag has published the Python packages.
#
# The importer is told not to run ansible-test, which needs a container
# runtime, and to require one of Galaxy's category tags, as Galaxy does.
#
# Run from anywhere, with ansible-galaxy, ansible-lint and galaxy-importer
# (the PyPI package) installed in the python3 on PATH:
#
#     tools/ci-check-ansible-collection.sh
#
# Set KEEP_WORK=1 to keep the temporary directory, which holds the
# tarball and the importer's result, for debugging.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

for tool in ansible-galaxy ansible-lint python3; do
    command -v "${tool}" > /dev/null || fail "${tool} not found on PATH"
done
python3 -c 'import galaxy_importer' 2> /dev/null \
    || fail 'python3 cannot import galaxy_importer: pip install galaxy-importer'

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ci-check-ansible-collection.XXXXXX")"
trap '[ -n "${KEEP_WORK:-}" ] || rm -rf "${WORK}"' EXIT

FAILED=()

echo '==> ansible-lint'
# From the repository root, so the config's relative paths and the
# project directory ansible-lint infers are the same wherever this is
# run from.
(cd "${REPO_ROOT}" && ansible-lint --nocolor -c ansible/.ansible-lint ansible/) \
    || FAILED+=('ansible-lint found problems in ansible/')

# build_and_import: build the collection and run galaxy-importer over
# the tarball, returning non-zero with the reason on stderr if either
# fails.
build_and_import() {
    echo '==> tools/build-collection.sh (the release build, version 0.0.1rc1)'
    mkdir -p "${WORK}/build"
    if ! "${REPO_ROOT}/tools/build-collection.sh" 0.0.1rc1 "${WORK}/build"; then
        echo 'the release build could not build the collection' >&2
        return 1
    fi
    local tarballs
    shopt -s nullglob
    tarballs=("${WORK}"/build/shakenfist-kerbside-*.tar.gz)
    shopt -u nullglob
    if [ "${#tarballs[@]}" -ne 1 ]; then
        echo "expected one shakenfist-kerbside tarball, found ${#tarballs[@]}" >&2
        return 1
    fi

    echo '==> galaxy-importer'
    # The importer writes importer_result.json to the current directory,
    # and ansible's local temporary files to ~/.ansible/tmp unless told
    # otherwise.
    mkdir -p "${WORK}/importer/ansible-tmp"
    if ! (
        cd "${WORK}/importer"
        GALAXY_IMPORTER_RUN_ANSIBLE_TEST=false \
        GALAXY_IMPORTER_CHECK_REQUIRED_TAGS=true \
        GALAXY_IMPORTER_ANSIBLE_LOCAL_TMP="${WORK}/importer/ansible-tmp" \
            python3 -m galaxy_importer.main "${tarballs[0]}"
    ); then
        echo "galaxy-importer refused ${tarballs[0]##*/}" >&2
        return 1
    fi
    TARBALL="${tarballs[0]##*/}"
}

build_and_import || FAILED+=('the collection did not build, or galaxy-importer refused it')

if [ "${#FAILED[@]}" -gt 0 ]; then
    for reason in "${FAILED[@]}"; do
        echo "FAIL: ${reason}" >&2
    done
    exit 1
fi
echo "ansible collection: lint, build and import passed (${TARBALL})"
