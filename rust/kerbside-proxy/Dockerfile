# Build image for the kerbside-proxy Rust crate. Kept deliberately minimal:
#   - build-essential + pkg-config: standard native build toolchain.
#   - git: required to fetch the shakenfist-spice-protocol git dependency.
#   - ca-certificates: TLS trust for the git fetch and crates.io.
# The rustls `ring` provider needs no OpenSSL or cmake, and protoc is vendored
# via the protoc-bin-vendored build-dependency, so no protobuf package is
# needed. Source is mounted at run time (see the Makefile), not COPYed in.
#
# This image is a build tool, not a runtime: the Makefile writes target/
# back to the host and proxy_supervisor.find_proxy_bin() then execs that
# binary on the developer's own machine. So the base's glibc is the
# binary's floor, and trixie's is 2.41 -- older than that on the host
# (Debian 12 has 2.36, Ubuntu 24.04 has 2.39) and the daemon's child
# dies with `version GLIBC_2.4x not found` rather than failing the
# build. On such a host, build the manylinux wheel with
# tools/build-proxy-wheel.sh instead, which zig pins to glibc 2.28.
FROM rust:slim-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# rustfmt and clippy ship with the official image, but add them explicitly so
# `make lint` works regardless of the base image's component set (idempotent).
RUN rustup component add rustfmt clippy
