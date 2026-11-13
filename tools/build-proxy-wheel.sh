#!/bin/bash
#
# Build a manylinux wheel for the kerbside-proxy crate for one target
# architecture. Used by the release workflow's wheel matrix (x86_64 and
# aarch64) and reproducible locally.
#
# Usage:
#   tools/build-proxy-wheel.sh x86_64     # cross/native manylinux (release)
#   tools/build-proxy-wheel.sh aarch64    # cross manylinux (release)
#   tools/build-proxy-wheel.sh --native   # plain host wheel, for local install
#
# Output wheels land in ${WHEEL_OUT:-<repo>/dist/proxy-wheels}.
#
# APPROACH: both architectures are built with maturin's `--zig` linker and
# `--compatibility manylinux_2_28`. zig supplies a pinned-glibc (2.28)
# sysroot, so the produced wheel honestly carries a manylinux_2_28 tag even
# when the build host has a newer glibc, and aarch64 is cross-compiled from
# an x86_64 host with no emulation. The vendored protoc (protoc-bin-vendored)
# runs on the BUILD host, so cross-compilation does not touch it.
#
# PREREQUISITES (provided by the caller/CI, not installed here):
#   - a Rust toolchain with rustup (the release workflow uses
#     dtolnay/rust-toolchain; the local Docker path uses the official rust
#     image). The target std library is added idempotently below.
#   - maturin and the `ziglang` Python package on PATH / importable
#     (`pip install maturin ziglang`).
#
# The build MUST run with the repository root available, because the crate's
# build.rs compiles ../../kerbside/rpc/kerbside.proto. This script cd's into
# the crate directory within the repo to satisfy that.
#
# FALLBACK (documented, not automated): if the zig cross of the
# ring/rustls/ryll dependency chain ever fails for aarch64, build the aarch64
# wheel inside the quay.io/pypa/manylinux_2_28_aarch64 image under
# binfmt/QEMU emulation instead (slower, but the canonical manylinux path).

# NATIVE MODE (--native): build a plain host-arch wheel with no zig, no forced
# manylinux tag, and no rustup target. This is for callers that build and
# INSTALL the wheel on the same machine (the direct-qemu Rust lane), where
# portability is irrelevant -- so it needs only maturin + a host cargo, not
# rustup/ziglang. Release wheels for distribution still use the per-arch
# manylinux/zig path above.

set -euo pipefail

native=0
arch="${1:-}"
case "${arch}" in
    x86_64)   triple="x86_64-unknown-linux-gnu" ;;
    aarch64)  triple="aarch64-unknown-linux-gnu" ;;
    --native) native=1 ;;
    *)
        echo "Usage: $0 <x86_64|aarch64|--native>" >&2
        exit 1
        ;;
esac

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
crate_dir="${repo_root}/rust/kerbside-proxy"
wheel_out="${WHEEL_OUT:-${repo_root}/dist/proxy-wheels}"

command -v maturin >/dev/null || { echo "ERROR: maturin not found on PATH" >&2; exit 1; }

mkdir -p "${wheel_out}"
cd "${crate_dir}"

# The published wheel must carry no cargo features. In particular `transcode`
# builds openh264 from vendored source, and the transcoding spike came back
# no-go: relaying with qemu's `streaming-video=all` matches or beats it almost
# everywhere, for a fraction of the CPU and no code. The transcoder therefore
# stays behind its build feature as an experiment that no wheel enables; see
# docs/performance/transcoding-spike.md. None of the ways to turn a feature on
# shows up in the wheel's name, so nothing downstream would notice.
#
# Two checks. The crate's own `default` list must be empty. And [tool.maturin]
# must carry nothing but the keys named below: `features`, `all-features` and
# `cargo-extra-args` all select features, and an earlier version of this check
# enumerated only the first, which is precisely how a wheel could have carried
# `transcode` while passing. maturin's full schema cannot be enumerated from
# here, so the table is deny-by-default: adding any key -- feature-selecting or
# not -- has to edit this allowlist, which is the intended tradeoff, and the
# happy path runs on every wheel build in rust.yml, release.yml,
# dev-proxy-wheel.yml and the three functional lanes.
#
# The tables are parsed rather than grepped: a line match also fired on
# `default = []` anywhere in the manifest, missed a reformatted `default=[]`,
# and refused a manifest that simply omits `default`, which cargo reads as
# empty.
if ! python3 -I - Cargo.toml pyproject.toml <<'FEATURE_CHECK'
import sys, tomllib

with open(sys.argv[1], 'rb') as f:
    default = tomllib.load(f).get('features', {}).get('default', [])
if default:
    sys.exit("ERROR: Cargo.toml's [features] default is %r, not empty: a default "
             'feature would be compiled into the published wheel.' % (default,))

# Keys [tool.maturin] may carry. Anything else, including any future
# feature-selecting key, is refused rather than assumed harmless.
ALLOWED = {'bindings'}
FEATURE_SELECTING = {'features', 'all-features', 'cargo-extra-args'}

with open(sys.argv[2], 'rb') as f:
    maturin = tomllib.load(f).get('tool', {}).get('maturin', {})
unexpected = sorted(set(maturin) - ALLOWED)
if unexpected:
    if FEATURE_SELECTING.intersection(unexpected):
        why = 'Those select cargo features, and the published wheel must carry none.'
    else:
        why = ('Unrecognised here; if a key cannot enable a cargo feature, add it to '
               'ALLOWED in this check.')
    sys.exit('ERROR: pyproject.toml sets [tool.maturin] %s. %s Allowed: %s.'
             % (', '.join(unexpected), why, ', '.join(sorted(ALLOWED))))
FEATURE_CHECK
then
    exit 1
fi

# A third feature check, independent of the two above and over the artefact
# rather than the inputs. The manifest checks read what this script asks
# cargo for; they cannot see a feature arriving by another route -- a
# dependency that enables it, a .cargo/config.toml in the tree, or a caller
# that invokes maturin itself with --features and never reaches this script.
# So the finished wheel is opened and the binary inside it searched for
# material only a `transcode` build can carry:
#
#   transcode-display  the clap long flag, which exists only inside
#                      #[cfg(feature = "transcode")]
#   openh264           the encoder the feature builds from vendored source
#
# Both are string data, not symbols, so the strip maturin applies to a
# release build leaves them in place.
#
# What this proves is narrow, and worth saying plainly: the published binary
# carries neither the transcoder's command-line surface nor any openh264.
# It is not a general feature audit -- a future feature with no string
# footprint would pass it -- which is why the deny-by-default manifest checks
# stay. Anything that stops it from answering (no binary in the wheel, an
# unreadable zip) fails the build rather than passing quietly.
#
# The check is guarded by a positive control and a provenance check below,
# because on its own it can only ever report nothing, and a search which
# reports nothing is indistinguishable from a search which is broken (the
# same reasoning as tools/gitleaks-scan.sh).
assert_wheel_carries_no_features() {
    python3 -I - "$1" <<'ARTEFACT_CHECK'
import sys, zipfile

# Marker -> what finding it would mean. Matched case-insensitively against the
# whole binary.
MARKERS = {
    b'transcode-display': 'the --transcode-display command-line flag',
    b'openh264': 'openh264, built from vendored source',
}

wheel = sys.argv[1]
try:
    with zipfile.ZipFile(wheel) as zf:
        # maturin's `bindings = "bin"` lays the binary into *.data/scripts/.
        binaries = [n for n in zf.namelist() if '.data/scripts/' in n and not n.endswith('/')]
        if len(binaries) != 1:
            sys.exit('ERROR: %s holds %d files under .data/scripts/, expected 1 (%r): this '
                     'check cannot say what the wheel carries.' % (wheel, len(binaries), binaries))
        blob = zf.read(binaries[0]).lower()
except (OSError, zipfile.BadZipFile) as e:
    sys.exit('ERROR: cannot read the built wheel %s: %s' % (wheel, e))

found = sorted(why for marker, why in MARKERS.items() if marker in blob)
if found:
    sys.exit('ERROR: the built binary %s in %s carries %s. A cargo feature reached this build '
             'by a route the manifest checks cannot see (a dependency, a cargo config, or a '
             'caller running maturin directly), and the published wheel must carry none.'
             % (binaries[0], wheel, '; '.join(found)))
ARTEFACT_CHECK
}

# The positive control for the check above. It is handed three wheel-shaped
# zips, laid out the way maturin lays out `bindings = "bin"`: one whose binary
# carries neither marker, and one per marker whose binary carries it in a
# different case. The check must accept the first and refuse the other two.
#
# That proves the zip-layout logic and the search itself -- that the binary is
# found under *.data/scripts/, read, and matched case-insensitively -- on every
# wheel build, for no measurable time. It does NOT prove the markers are the
# right markers: a synthetic binary says nothing about what a real `transcode`
# build emits. The honest way to prove that is to build a wheel with the
# feature on and watch the check refuse it, and that build compiles openh264
# from vendored source, which is too expensive to put in front of every wheel.
# The provenance check below is the cheap half of that claim: it fails if
# either marker stops being something a transcode build would carry, so a
# renamed clap flag or an openh264 arriving under another crate name breaks
# the build instead of rotting into a check that passes for ever.
assert_artefact_check_fires() {
    local control rc=0
    control="$(mktemp -d)"
    python3 -I - "${control}" <<'MAKE_CONTROLS'
import os, sys, zipfile

control = sys.argv[1]
# One binary, where maturin's `bindings = "bin"` puts it.
BINARY = 'kerbside_proxy-0.0.0.data/scripts/kerbside-proxy'
FILLER = b'\x7fELF' + b'\0' * 12 + b'not a binary, just bytes to search\n'


def write(name, extra=b''):
    with zipfile.ZipFile(os.path.join(control, name), 'w') as zf:
        zf.writestr(BINARY, FILLER + extra)


write('clean.whl')
# Mixed case on purpose: the check lowercases the blob it reads, and one that
# only matched the case the markers happen to be written in would be weaker
# than it looks.
write('transcode-display.whl', b'--Transcode-Display\n')
write('openh264.whl', b'OpenH264 2.4.1\n')
MAKE_CONTROLS

    if ! assert_wheel_carries_no_features "${control}/clean.whl"; then
        echo "ERROR: the artefact check refused a control wheel carrying neither marker." >&2
        rc=1
    fi
    for marker in transcode-display openh264; do
        if assert_wheel_carries_no_features "${control}/${marker}.whl" 2>/dev/null; then
            echo "ERROR: the artefact check accepted a control wheel whose binary carries" >&2
            echo "       ${marker}. Do not trust it against a real wheel until this passes." >&2
            rc=1
        fi
    done
    rm -rf "${control}"
    return "${rc}"
}

# Both markers must still be material a `transcode` build carries. Checked
# against the crate rather than the binary, so it costs nothing and runs
# before the build:
#
#   transcode-display  must appear in src/. The declaration itself is a clap
#                      field, `transcode_display`, from which clap derives the
#                      hyphenated flag; what this grep matches is the prose and
#                      the parse tests that spell the flag out. That is the
#                      weaker half on its own, and what makes a rename loud is
#                      main.rs's assertion that --help contains this exact
#                      string: a renamed flag fails the crate's tests. The grep
#                      covers the case where that text is removed altogether,
#                      which would leave the marker searching for nothing.
#   openh264           must still be the name of a crate in the resolved
#                      dependency graph. Nothing but the transcode feature's
#                      two optional ryll dependencies pulls it in.
#
# If either fails, the marker is the thing to fix, not this check: find what
# the feature now carries and search for that instead.
assert_markers_are_still_transcode_material() {
    local rc=0
    if ! grep -rq -- 'transcode-display' src/; then
        echo "ERROR: 'transcode-display' no longer appears in src/, so searching a wheel" >&2
        echo "       for it proves nothing. Has the clap flag been renamed?" >&2
        rc=1
    fi
    if ! grep -q '^name = "openh264"$' Cargo.lock; then
        echo "ERROR: no crate named openh264 in Cargo.lock, so searching a wheel for it" >&2
        echo "       proves nothing. Does the transcoder still encode H.264, and under" >&2
        echo "       what crate name?" >&2
        rc=1
    fi
    return "${rc}"
}

assert_markers_are_still_transcode_material
assert_artefact_check_fires
echo "Feature checks armed: the artefact check refuses both markers."

# If the tree is unstamped (pyproject.toml still declares a dynamic version,
# which maturin resolves from Cargo.toml's 0.1.0 placeholder), stamp the
# setuptools_scm version first. kerbside's committed dependency floor
# (kerbside-proxy>=X.Y.Z.dev0) rejects a 0.1.0 wheel, so an unstamped local
# wheel cannot be co-installed with kerbside. The stamp is reverted on exit
# so the working tree is left as found. Requires setuptools_scm and full git
# history (a shallow clone cannot count commits since the last v* tag).
#
# setuptools_scm usually gives a dev version, but on a clean checkout of a
# v* tag it gives the release version itself, which
# tools/stamp-dev-proxy-version.sh refuses -- it guards the dev publishing
# path, which must never publish a release version. Every lane that runs on
# develop met that the night after each release, when develop still sat on
# the tag (#578). A release version builds fine and satisfies the floor, so
# it is stamped here directly, into the crate pyproject the trap restores.
# tools/stamp-proxy-version.sh is not used, because it also rewrites
# Cargo.toml and kerbside's own pin, which a local build must not leave
# behind.
#
# This block CANNOT fire on a release build: tools/stamp-proxy-version.sh
# replaces the `dynamic = ["version"]` declaration with a static release
# version, so on a release-stamped tree the grep below does not match. The
# tree state, not call ordering, is what keeps the two stamp modes apart
# (tools/verify-wheel-stamping.sh asserts both modes in CI).
# Anchored at both ends deliberately: tools/stamp-proxy-version.sh and
# tools/stamp-dev-proxy-version.sh test this same line in this same file, and
# all three must agree about whether the tree is stamped.
if grep -q '^dynamic = \["version"\]$' pyproject.toml; then
    echo "Unstamped tree: stamping the setuptools_scm dev version..."
    saved_pyproject="$(mktemp)"
    cp pyproject.toml "${saved_pyproject}"
    restore_pyproject() {
        cat "${saved_pyproject}" > pyproject.toml
        rm -f "${saved_pyproject}"
    }
    trap restore_pyproject EXIT
    version="$( { cd "${repo_root}" && python3 -m setuptools_scm; } 2>/dev/null || true)"
    version="${version%%+*}"
    if [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "HEAD is the release ${version}: stamping it as a static version..."
        sed -i "s/^dynamic = \[\"version\"\]\$/version = \"${version}\"/" pyproject.toml
    else
        "${repo_root}/tools/stamp-dev-proxy-version.sh" ${version:+"${version}"}
    fi
fi

if [ "${native}" = 1 ]; then
    echo "Building kerbside-proxy wheel for the host (native, no zig/manylinux)..."
    maturin build --release --out "${wheel_out}"
    # Accept whatever platform tag maturin produces for the host; a native
    # host wheel is not required to be manylinux-tagged. Wheel filenames
    # cannot contain whitespace, so ls -t is a safe way to pick the newest.
    # shellcheck disable=SC2012
    wheel="$(ls -1t "${wheel_out}"/*.whl 2>/dev/null | head -1 || true)"
    if [ -z "${wheel}" ]; then
        echo "ERROR: no wheel produced in ${wheel_out}" >&2
        exit 1
    fi
    assert_wheel_carries_no_features "${wheel}"
    echo "OK: $(basename "${wheel}")"
    exit 0
fi

command -v rustup >/dev/null || { echo "ERROR: rustup not found on PATH" >&2; exit 1; }

# Idempotently ensure the target std library is present.
rustup target add "${triple}"

echo "Building kerbside-proxy wheel for ${arch} (${triple}), manylinux_2_28, zig linker..."
maturin build \
    --release \
    --target "${triple}" \
    --zig \
    --compatibility manylinux_2_28 \
    --out "${wheel_out}"

# Verify a manylinux wheel for the expected architecture was produced.
# Wheel filenames cannot contain whitespace, so ls -t safely picks the newest.
# shellcheck disable=SC2012
wheel="$(ls -1t "${wheel_out}"/*"${arch}".whl 2>/dev/null | head -1 || true)"
if [ -z "${wheel}" ]; then
    echo "ERROR: no *${arch}.whl produced in ${wheel_out}" >&2
    exit 1
fi
case "$(basename "${wheel}")" in
    *manylinux*"${arch}".whl) ;;
    *)
        echo "ERROR: produced wheel is not manylinux-tagged: $(basename "${wheel}")" >&2
        exit 1
        ;;
esac

assert_wheel_carries_no_features "${wheel}"

echo "OK: $(basename "${wheel}")"
