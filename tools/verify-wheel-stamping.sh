#!/bin/bash
#
# Verify tools/build-proxy-wheel.sh produces correctly versioned wheels in
# BOTH stamp modes, so a stamping regression surfaces on PRs rather than at
# release time (when the tag already exists):
#
#   1. Unstamped tree: the dev auto-stamp must fire, the wheel must carry a
#      PEP 440 dev version (never Cargo.toml's 0.1.0 placeholder), and the
#      crate pyproject must be restored afterwards.
#   2. Unstamped tree checked out at a v* tag: setuptools_scm gives the
#      release version itself, so the wheel must carry exactly that version
#      (the dev stamp refuses it, which failed every nightly lane the night
#      after each release, #578), and the crate pyproject must be restored.
#   3. Release-stamped tree (tools/stamp-proxy-version.sh 9.9.9): the auto
#      dev-stamp must NOT fire, the wheel must be exactly 9.9.9, and the
#      kerbside dependency list must hold exactly one kerbside-proxy line
#      (==9.9.9), idempotent across a second stamp.
#
# Requires maturin, setuptools_scm and full git history (like the lanes it
# guards). Dirties the tree (release stamp) and restores it with git
# checkout at the end, so run it on a throwaway checkout or a clean tree.
# Mode 2 also tags HEAD with a local, never-pushed v9.9.8 and deletes it at
# the end; it is skipped on a tree with any uncommitted change, because
# setuptools_scm then gives a dev version whatever the tag.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo_root}"

# Cargo.lock is in the list because building with the 9.9.9-stamped
# Cargo.toml rewrites the lock's own package version entry.
stamped_files=(rust/kerbside-proxy/Cargo.toml rust/kerbside-proxy/Cargo.lock
               rust/kerbside-proxy/pyproject.toml pyproject.toml)

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The restore trap is a `git checkout` of the stamped files, so it MUST only
# be armed once they are known clean -- otherwise a failed precondition
# would destroy uncommitted edits.
for f in "${stamped_files[@]}"; do
    git diff --quiet -- "${f}" || fail "${f} is dirty; verify-wheel-stamping.sh needs a clean tree"
done

tagged_version=9.9.8
tagged_tag="v${tagged_version}"
git rev-parse --quiet --verify "refs/tags/${tagged_tag}" >/dev/null \
    && fail "tag ${tagged_tag} already exists; mode 2 needs to create and delete it"
tag_created=0

restore() {
    git checkout --quiet -- "${stamped_files[@]}"
    if [ "${tag_created}" = 1 ]; then
        git tag --delete "${tagged_tag}" >/dev/null
    fi
}
trap restore EXIT

out_dev="$(mktemp -d)"
out_tag="$(mktemp -d)"
out_rel="$(mktemp -d)"

# ── Mode 1: unstamped tree → dev-versioned wheel ─────────────────────────────
echo "=== Mode 1: unstamped tree (dev auto-stamp) ==="
WHEEL_OUT="${out_dev}" tools/build-proxy-wheel.sh --native
ls "${out_dev}"/kerbside_proxy-*.dev*-*.whl >/dev/null 2>&1 \
    || fail "unstamped build did not produce a dev-versioned wheel: $(ls "${out_dev}")"
ls "${out_dev}"/kerbside_proxy-0.1.0-*.whl >/dev/null 2>&1 \
    && fail "unstamped build produced the 0.1.0 placeholder wheel"
git diff --quiet -- rust/kerbside-proxy/pyproject.toml \
    || fail "dev auto-stamp did not restore rust/kerbside-proxy/pyproject.toml"

# ── Mode 2: unstamped tree at a v* tag → release-versioned wheel ─────────────
echo "=== Mode 2: unstamped tree at tag ${tagged_tag} ==="
if git diff --quiet HEAD; then
    git tag "${tagged_tag}" HEAD
    tag_created=1
    WHEEL_OUT="${out_tag}" tools/build-proxy-wheel.sh --native
    ls "${out_tag}"/kerbside_proxy-"${tagged_version}"-*.whl >/dev/null 2>&1 \
        || fail "unstamped build at ${tagged_tag} did not produce a ${tagged_version} wheel: $(ls "${out_tag}")"
    git diff --quiet -- rust/kerbside-proxy/pyproject.toml \
        || fail "release auto-stamp did not restore rust/kerbside-proxy/pyproject.toml"
    git tag --delete "${tagged_tag}" >/dev/null
    tag_created=0
else
    echo "SKIP: the tree has uncommitted changes, so setuptools_scm would give a dev version"
fi

# ── Mode 3: release-stamped tree → exact-versioned wheel ─────────────────────
echo "=== Mode 3: release-stamped tree (9.9.9) ==="
tools/stamp-proxy-version.sh 9.9.9
grep -q '^version = "9.9.9"$' rust/kerbside-proxy/pyproject.toml \
    || fail "release stamp did not write a static version into the crate pyproject"
WHEEL_OUT="${out_rel}" tools/build-proxy-wheel.sh --native
ls "${out_rel}"/kerbside_proxy-9.9.9-*.whl >/dev/null 2>&1 \
    || fail "release-stamped build did not produce a 9.9.9 wheel: $(ls "${out_rel}")"

# Floor-to-pin replacement and idempotence in the kerbside dependency list.
count="$(grep -c '"kerbside-proxy' pyproject.toml || true)"
[ "${count}" = "1" ] || fail "expected exactly one kerbside-proxy line after stamping, got ${count}"
grep -q '"kerbside-proxy==9.9.9"' pyproject.toml || fail "kerbside-proxy line is not the ==9.9.9 pin"
tools/stamp-proxy-version.sh 9.9.9
count="$(grep -c '"kerbside-proxy' pyproject.toml || true)"
[ "${count}" = "1" ] || fail "re-stamping duplicated the kerbside-proxy line (${count} found)"

echo "OK: dev wheel $(basename "$(ls "${out_dev}"/kerbside_proxy-*.whl)"), release wheel $(basename "$(ls "${out_rel}"/kerbside_proxy-*.whl)")"
