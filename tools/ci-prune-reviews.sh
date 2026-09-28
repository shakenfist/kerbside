#!/bin/bash -e

# Prune stale review marks, import reviews of identical content from
# shakenfist/development, and commit both back to the default branch
# as one unsigned bot commit. Run by the prune-reviews workflow, which
# supplies DEFAULT_BRANCH and RUNNER_TEMP; it pushes, so it is not for
# running by hand. See "Steady state" in
# https://github.com/shakenfist/development/blob/main/docs/code-review-tracking.md
#
# This file is copied byte-for-byte from templates/review-tracking/ in
# shakenfist/development into every adopted repository, that
# repository included. Change the template, not a copy.

# The gitsign release import verifies signatures with. The digest is
# the linux_amd64 binary's, from that release's checksums.txt; bump
# the two together.
GITSIGN_VERSION='0.17.1'
GITSIGN_SHA256='69213a8a0813a151e5a47d0060862952ff833a845d57309dff76f7ba6600abae'

: "${DEFAULT_BRANCH:?DEFAULT_BRANCH must name the branch to commit to}"
: "${RUNNER_TEMP:?RUNNER_TEMP must name a scratch directory}"

# Download the pinned gitsign and put it first on PATH. The static
# runners do not carry gitsign, and without it import imports nothing.
# The download is checked twice: the release's checksums.txt must list
# the pinned digest for the binary, which catches a version bumped
# without its digest, and the binary must hash to it, which is what
# actually pins what runs.
install_gitsign() {
    local dir="${RUNNER_TEMP}/gitsign"
    local asset="gitsign_${GITSIGN_VERSION}_linux_amd64"
    local base="https://github.com/sigstore/gitsign/releases/download/v${GITSIGN_VERSION}"
    local expected="${GITSIGN_SHA256}  ${asset}"

    if [ "$(uname -m)" != 'x86_64' ]; then
        echo "This script installs the linux_amd64 gitsign, but this runner is $(uname -m)." >&2
        exit 1
    fi

    rm -rf "${dir}"
    mkdir -p "${dir}"
    curl -fsSL --retry 3 -o "${dir}/${asset}" "${base}/${asset}"
    curl -fsSL --retry 3 -o "${dir}/checksums.txt" "${base}/checksums.txt"
    if ! grep -qxF "${expected}" "${dir}/checksums.txt"; then
        echo "gitsign v${GITSIGN_VERSION}'s checksums.txt does not list ${expected}." >&2
        exit 1
    fi
    (cd "${dir}" && echo "${expected}" | sha256sum --check --strict)
    mv "${dir}/${asset}" "${dir}/gitsign"
    chmod 0755 "${dir}/gitsign"
    export PATH="${dir}:${PATH}"
    gitsign version | head -n 1
}

# Clone shakenfist/development for the review tracking script and for
# the review history import reads -- all of it, not a depth 1 clone,
# because a copy here often matches an older revision of a file that
# was reviewed there, and only the history still records that review.
# tools/review-tracking.sh finds the clone through
# SHAKENFIST_DEVELOPMENT. In shakenfist/development itself the wrapper
# runs the script in its own tree and ignores this clone, and import
# there is a no-op.
clone_development() {
    local dir="${RUNNER_TEMP}/development"

    rm -rf "${dir}"
    git clone --quiet https://github.com/shakenfist/development "${dir}"
    export SHAKENFIST_DEVELOPMENT="${dir}"
}

# Refuse to report success over review state git cannot see. In a
# repository that ignores .vscode/ without the .gitignore exception
# for the sidecars, the imports file import writes is ignored: git
# status does not list it and git add does not stage it, so every run
# would clone, verify and import the same reviews, commit nothing, and
# go green. The same holds for a REVIEWS.md that is gitignored before
# it is first generated. git check-ignore reports only untracked
# files, which is exactly the case that matters -- a tracked file is
# staged either way.
check_state_is_committable() {
    local paths ignored rc=0

    shopt -s nullglob
    paths=(.vscode/*.weaudit-shas.json)
    shopt -u nullglob
    if [ -e REVIEWS.md ]; then
        paths+=(REVIEWS.md)
    fi
    if [ "${#paths[@]}" -eq 0 ]; then
        return
    fi
    ignored="$(git check-ignore -- "${paths[@]}")" || rc=$?
    if [ "${rc}" -gt 1 ]; then
        exit "${rc}"
    fi
    if [ -n "${ignored}" ]; then
        echo 'These review state files are gitignored, so they can never be committed:' >&2
        echo "${ignored}" >&2
        echo 'REVIEWS.md must not be ignored at all. For the sidecars, add the .gitignore' >&2
        echo 'exception for .vscode/*.weaudit-shas.json, ignoring .vscode/* rather than' >&2
        echo '.vscode/ so that the exception can apply: step 1 of "Adopting a repository"' >&2
        echo 'in docs/code-review-tracking.md in shakenfist/development.' >&2
        exit 1
    fi
}

# Land the review state on the default branch, regenerating it on
# every attempt rather than rebasing a commit made earlier. Everything
# committed here is derived from the tree it is committed on top of,
# so resetting to the branch's current tip and running prune and
# import again always produces the right commit and can never
# conflict. It also prunes marks for any file that a merge landing
# mid-run changed, which a rebase would carry over unpruned. The
# workflow checked out the commit that triggered it, which may
# already be behind; the reset to the fetched tip is intended.
#
# The concurrency group serialises these runs against each other but
# not against human merges, so a merge can still land between the
# fetch and the push and get the push rejected as non-fast-forward.
# The retry is what closes that window: without it the run goes red
# for a reason unrelated to correctness, which is how a workflow
# trains people to stop reading it. Only that rejection is retried.
# A push refused for any other reason -- a token that cannot write,
# a ruleset that wants a pull request -- fails at once with the
# push's own error, since regenerating would not change the answer;
# so does a failing fetch, prune or import, under -e. The push runs
# under LC_ALL=C so that its rejection reason can be matched.
land() {
    local attempts=3 attempt push_output

    git config user.name 'shakenfist-bot'
    git config user.email 'bot@shakenfist.com'

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        git fetch --quiet origin "${DEFAULT_BRANCH}"
        git reset --quiet --hard FETCH_HEAD

        # Prune first: import will not import over a native mark,
        # stale or not, until prune has removed it.
        tools/review-tracking.sh prune
        tools/review-tracking.sh import
        check_state_is_committable

        # git status --porcelain rather than git diff --quiet: the
        # latter only sees tracked paths, and import creates
        # .vscode/imports.weaudit-shas.json the first time it imports
        # anything. A new file missed here would be silently
        # discarded when the workspace is next cleaned.
        if [ -z "$(git status --porcelain -- .vscode/ REVIEWS.md)" ]; then
            echo 'No review marks to prune or import.'
            exit 0
        fi

        git add .vscode/ REVIEWS.md
        git commit --quiet -m 'Prune and import review marks.

Automated commit by the prune-reviews workflow.'

        if push_output="$(LC_ALL=C git push origin "HEAD:${DEFAULT_BRANCH}" 2>&1)"; then
            echo "${push_output}"
            exit 0
        fi
        echo "${push_output}" >&2
        case "${push_output}" in
            *'(fetch first)'* | *'(non-fast-forward)'*) ;;
            *)
                echo 'The push was refused, and not because a merge landed first. Check the' >&2
                echo 'token and ruleset requirements in templates/review-tracking/README.md' >&2
                echo 'in shakenfist/development.' >&2
                exit 1
                ;;
        esac
        # Only claim a retry that is actually coming.
        if [ "${attempt}" -lt "${attempts}" ]; then
            echo "Landing attempt ${attempt} of ${attempts} was rejected; retrying."
            sleep 5
        fi
    done

    echo "Could not land the review state after ${attempts} attempts." >&2
    exit 1
}

run() {
    # Everything uses relative paths and relative git pathspecs, so
    # anchor to the root of the repository this script is in rather
    # than trusting the caller's cwd. An assignment, so that set -e
    # stops the run if git cannot find it; a bare cd "$(...)" would
    # carry on wherever it was.
    local repo_root
    repo_root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
    cd "${repo_root}"

    install_gitsign
    clone_development
    land
}

# All of the work is in functions, called from the last line, because
# land resets the checkout, and a merge that changed this file would
# otherwise have bash read the rest of it at a stale offset.
run "$@"
