#!/bin/bash
# Bring up the compose demo for the CI lane.
#
# Builds the demo image against the CHECKOUT rather than the released
# package, and brings the stack to healthy. After this exits 0,
# lane-assert.sh can run.
#
# The lane deliberately diverges from what a user runs here. The demo's
# default installs released kerbside from PyPI, which is right for an
# evaluator and useless for CI: it would test the last release instead
# of the pull request. So the lane sets KERBSIDE_SOURCE=/src and is the
# only place that does.
#
# There is no cargo step anywhere in this lane, and that is deliberate.
# pyproject.toml carries a dev-inclusive floor (kerbside-proxy>=X.dev0),
# so a checkout install resolves the newest dev wheel published from
# develop by dev-proxy-wheel.yml and the daemon is paired with a binary
# that tracks develop. See demo/Dockerfile and the phase 4 plan.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEMO_DIR="${REPO_ROOT}/demo"

# Long enough for a cold image build plus a database initialising plus
# `kerbside db upgrade`, and short enough that a hung lane does not sit
# for the job timeout. The compose healthcheck's own start_period is
# 120s, so this has to exceed it comfortably.
WAIT_TIMEOUT="${WAIT_TIMEOUT:-600}"

cd "${DEMO_DIR}"

# ── Dump everything a failure needs, then fail ───────────────────────
#
# A bare "up --wait timed out" is close to useless: the interesting
# information is which service is unhealthy and what it last said. This
# runs on any failure path below, so the lane's log always carries the
# diagnosis rather than requiring an artifact download to start
# guessing.
dump_and_die() {
    echo "::group::docker compose ps"
    docker compose ps --all || true
    echo "::endgroup::"
    for svc in db spice-target kerbside; do
        echo "::group::docker compose logs ${svc}"
        docker compose logs --no-color "${svc}" 2>&1 | tail -200 || true
        echo "::endgroup::"
    done
    echo "ERROR: $1" >&2
    exit 1
}

# ── Step 1: A clean slate ────────────────────────────────────────────
#
# `down -v` and not just `down`: the state volume holds the generated CA
# and the JWT signing seed, and a lane that reused them would not be
# testing first-run generation, which is the path every evaluator takes.
echo "[lane-up] Removing any previous stack"
docker compose down -v --remove-orphans > /dev/null 2>&1 || true

# ── Step 2: Validate before building ─────────────────────────────────
#
# Seconds, and it catches a compose schema error or a Dockerfile syntax
# error before a multi-minute image build. Cheap enough that the lane
# runs it even though `up` would eventually report the same fault.
echo "[lane-up] Validating the compose file"
docker compose config > /dev/null \
    || dump_and_die "demo/docker-compose.yml is not valid"

# ── Step 3: Build against the checkout ───────────────────────────────
#
# KERBSIDE_SOURCE=/src needs the repository's git metadata in the build
# context: setuptools_scm's file finder is the only thing that installs
# kerbside/sources/ and kerbside/migrations/, neither of which has an
# __init__.py. The workflow therefore checks out with fetch-depth: 0,
# and .dockerignore deliberately does not exclude .git. Without either,
# the install succeeds and then dies at import with "No module named
# 'kerbside.sources'".
echo "[lane-up] Building the demo image from the checkout"
KERBSIDE_SOURCE=/src docker compose build \
    || dump_and_die "the demo image failed to build"

# ── Step 4: Up, and let compose do the waiting ───────────────────────
#
# --wait rather than a hand-rolled poll: the healthchecks in
# docker-compose.yml are already the authority on readiness, and
# get-console.sh waits on the same signal. Duplicating that logic here
# would give the lane a second, subtly different definition of ready.
echo "[lane-up] Starting the stack (timeout ${WAIT_TIMEOUT}s)"
KERBSIDE_SOURCE=/src timeout "${WAIT_TIMEOUT}" \
    docker compose up -d --wait \
    || dump_and_die "the stack did not become healthy within ${WAIT_TIMEOUT}s"

echo "[lane-up] Stack is up:"
docker compose ps

# Record what was actually installed. When a contract-hash refusal or a
# packaging regression shows up, the first question is always "which
# versions", and a lane that has to be re-run to answer it wastes a
# cycle.
echo "[lane-up] Installed kerbside versions:"
docker compose exec -T kerbside pip list 2>/dev/null \
    | grep -i '^kerbside' || true

echo "[lane-up] complete"
