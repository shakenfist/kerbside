#!/bin/bash -e

# Prune stale review marks, import reviews of identical content from
# shakenfist/development, and commit both back to the default branch
# as one unsigned bot commit. Run by the prune-reviews workflow, which
# supplies DEFAULT_BRANCH and PUSH_TOKEN (the runner supplies
# GITHUB_REPOSITORY and RUNNER_TEMP); it pushes, so it is not for
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
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must name the repository to land on, as owner/name}"
: "${PUSH_TOKEN:?PUSH_TOKEN must hold a token that can push to DEFAULT_BRANCH}"

# The token, out of the environment, so that nothing this script runs
# inherits it: not curl, not gitsign, and not the review tracking
# script from the development clone. Only push_review_state hands it
# on, to the one git push.
take_push_token() {
    push_token="${PUSH_TOKEN}"
    unset PUSH_TOKEN
}

# Isolate git and gitsign from state left on the runner. The static
# runners are long-lived, share one home directory across jobs and
# repositories, and run pull request code, so ~/.gitconfig and
# ~/.sigstore are writable by any earlier job. A url.<x>.insteadOf
# there could swap the development clone, whose script this job runs,
# for another; a poisoned TUF cache could change which Fulcio roots
# and Rekor keys gitsign trusts, or, through its remote.json, which
# mirror it updates them from. The workspace's own .git is reused
# state too, which is why nothing here runs git in it (clone_target).
#
# GIT_CONFIG_GLOBAL=/dev/null replaces both ~/.gitconfig and
# $XDG_CONFIG_HOME/git/config, and GIT_CONFIG_NOSYSTEM skips the
# system file, leaving only the config of the clones this script
# makes. GIT_CEILING_DIRECTORIES stops git looking for a repository
# above RUNNER_TEMP: on a self-hosted runner that is _work, the runner
# directory and the home directory, all writable by an earlier job, so
# a .git planted there is never discovered. land sets the commit identity in the target's, since nothing
# global supplies it any more. That drops runner-wide settings an
# operator meant, too: a runner that needs a proxy or a private CA
# must supply it through the environment (HTTPS_PROXY,
# GIT_SSL_CAINFO), which git still reads.
#
# TUF_ROOT moves gitsign's cache to a fresh directory per run. Checked
# against the source gitsign v0.17.1 builds with: sigstore/sigstore's
# pkg/tuf (TufRootEnv, read by rootCacheDir; default ~/.sigstore/root)
# backs the Fulcio roots and cosign.GetRekorPubs/GetCTLogPubs, and
# cosign v3.1.2's TrustedRoot() hands the same variable to
# sigstore-go's TUF client as its CachePath (env.VariableTUFRootDir),
# so the one variable covers every cache verification reads. An empty
# cache starts from the root embedded in the gitsign binary, whose
# digest install_gitsign pins.
isolate_from_runner() {
    export GIT_CONFIG_GLOBAL=/dev/null
    export GIT_CONFIG_NOSYSTEM=1
    GIT_CEILING_DIRECTORIES="$(dirname "${RUNNER_TEMP}")"
    export GIT_CEILING_DIRECTORIES
    export TUF_ROOT="${RUNNER_TEMP}/sigstore-root"
    rm -rf "${TUF_ROOT}"
    mkdir -p "${TUF_ROOT}"
}

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
# there is a no-op. A plain clone, because import walks the clone's
# remote-tracking ref for the default branch, which only a plain clone
# is sure to create. The URL is fixed here; nothing in the
# environment can change it, which is why the tests redirect it with
# a git on PATH instead.
clone_development() {
    local dir="${RUNNER_TEMP}/development"

    rm -rf "${dir}"
    git clone --quiet https://github.com/shakenfist/development "${dir}"
    export SHAKENFIST_DEVELOPMENT="${dir}"
}

# Clone the repository being landed on into RUNNER_TEMP, and work
# there rather than in the runner's workspace. A static runner reuses
# its workspace, .git included: hooks an earlier pull request job left
# in .git/hooks would run on this job's fetch, reset and commit, and
# keys it left in .git/config -- core.fsmonitor, an include.path, a
# pushurl or url.<x>.insteadOf -- would run commands or redirect the
# push. A fresh clone has neither. The workflow fetches this script
# the same way, so nothing in the job reads the workspace at all. The
# URL comes from GITHUB_REPOSITORY, which the runner sets for every
# job; like the development clone's, nothing an earlier job could
# write changes it. Depth 1, because prune and import never read this
# repository's history -- only the development clone's is walked --
# which scripts/tests/test_review_tracking.py in shakenfist/development
# pins by running both in a shallow clone.
clone_target() {
    local dir="${RUNNER_TEMP}/target"

    rm -rf "${dir}"
    git clone --quiet --depth 1 --branch "${DEFAULT_BRANCH}" \
        "https://github.com/${GITHUB_REPOSITORY}" "${dir}"
    cd "${dir}"
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

# Keep a copy of the review state as prune left it, for land to put
# back if import fails part way through writing. A copy of the files
# rather than git add: in a repository that ignores .vscode/ outright,
# git add refuses the directory before check_state_is_committable can
# say why, and staging would also need deleted and untracked paths
# handled separately. Only what exists is copied, so that a prune
# that left no .vscode or REVIEWS.md is put back as it was: restore
# removes both before copying the saved state over.
save_prune_result() {
    local saved="${RUNNER_TEMP}/after-prune" path

    rm -rf "${saved}"
    mkdir -p "${saved}"
    for path in .vscode REVIEWS.md; do
        if [ -e "${path}" ]; then
            cp -a "${path}" "${saved}/"
        fi
    done
}

restore_prune_result() {
    rm -rf .vscode REVIEWS.md
    cp -a "${RUNNER_TEMP}/after-prune/." .
}

# Land the review state on the default branch, regenerating it on
# every attempt rather than rebasing a commit made earlier. Everything
# committed here is derived from the tree it is committed on top of,
# so resetting to the branch's current tip and running prune and
# import again always produces the right commit and can never
# conflict. It also prunes marks for any file that a merge landing
# mid-run changed, which a rebase would carry over unpruned. The
# workflow's trigger may already be behind the branch; the clone, and
# each retry's reset to the fetched tip, are of the branch as it is.
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
# so does a failing fetch or prune, under -e. The push runs under
# LC_ALL=C so that its rejection reason can be matched.
#
# A failing import is different, because prune's result does not
# depend on it. Prune is what stops a changed file reading as
# reviewed, so a run that threw prune's result away because import
# failed would leave stale marks counting until import was fixed.
# Instead prune's result is saved before import runs; if import
# fails, whatever it wrote is put back to that, prune's result lands
# alone, and the run fails after landing (finish) so that the import
# failure is still seen. Only the last attempt's import counts: one
# that fails and then succeeds after a race has landed everything.
land() {
    local attempts=3 attempt push_output import_rc

    git config user.name 'shakenfist-bot'
    git config user.email 'bot@shakenfist.com'

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        git fetch --quiet --depth 1 origin "${DEFAULT_BRANCH}"
        git reset --quiet --hard FETCH_HEAD

        # Prune first: import will not import over a native mark,
        # stale or not, until prune has removed it.
        tools/review-tracking.sh prune
        save_prune_result

        import_rc=0
        tools/review-tracking.sh import || import_rc=$?
        if [ "${import_rc}" -ne 0 ]; then
            echo "ERROR: review-tracking.sh import failed with exit ${import_rc}. Discarding what it" >&2
            echo "wrote and landing prune's result alone; the run will fail once that has landed." >&2
            restore_prune_result
        fi
        check_state_is_committable

        # git status --porcelain rather than git diff --quiet: the
        # latter only sees tracked paths, and import creates
        # .vscode/imports.weaudit-shas.json the first time it imports
        # anything. A new file missed here would be silently
        # discarded when the workspace is next cleaned.
        if [ -z "$(git status --porcelain -- .vscode/ REVIEWS.md)" ]; then
            echo 'No review marks to prune or import.'
            finish "${import_rc}"
        fi

        git add .vscode/ REVIEWS.md
        git commit --quiet -m 'Prune and import review marks.

Automated commit by the prune-reviews workflow.'

        if push_output="$(push_review_state 2>&1)"; then
            echo "${push_output}"
            finish "${import_rc}"
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

# Push HEAD to the default branch, the one git command given the token.
# Neither clone holds credentials, so the token reaches git here as an
# http.extraheader for github.com, through GIT_CONFIG_COUNT and friends
# on this command alone: never in argv, where any process on the runner
# could read it, and never in .git/config, where it would outlive the
# push. The environment of git push and its git-remote-https child is
# still readable, through /proc/<pid>/environ, by any process running
# as the runner's own user while the push runs; what bounds that is the
# runner killing a job's orphaned processes when the job ends, and the
# fresh clone, whose empty hooks directory gives an earlier job's code
# no way to start one inside this job. printf is a builtin, so the
# token is not in base64's argv either. LC_ALL=C keeps the rejection
# reason matchable.
push_review_state() {
    local header

    header="AUTHORIZATION: basic $(printf 'x-access-token:%s' "${push_token}" | base64 -w 0)"
    LC_ALL=C GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0='http.https://github.com/.extraheader' GIT_CONFIG_VALUE_0="${header}" \
        git push origin "HEAD:${DEFAULT_BRANCH}"
}

# The end of a run that got its review state onto the default branch,
# or found nothing to put there. It succeeds unless that state is
# prune's alone because import failed, in which case the failure that
# land reported when it happened is repeated last, where it is seen.
# Takes import's exit status from the last attempt.
finish() {
    local import_rc="$1"

    if [ "${import_rc}" -ne 0 ]; then
        echo "ERROR: review-tracking.sh import failed with exit ${import_rc}, so nothing was" >&2
        echo "imported; prune's result, if it had one, has landed. See import's output above." >&2
        exit 1
    fi
    exit 0
}

run() {
    # Before anything else runs: the first command would otherwise
    # inherit the token, and the first git command the runner's config.
    take_push_token
    isolate_from_runner
    # Out of the workspace before any git command, so that none of them
    # can discover the reused .git there.
    cd "${RUNNER_TEMP}"

    install_gitsign
    clone_development
    # Everything after this uses relative paths and relative git
    # pathspecs, in the target's clone.
    clone_target
    land
}

# All of the work is in functions, called from the last line, so that
# bash has read the whole file before any of it runs.
run "$@"
