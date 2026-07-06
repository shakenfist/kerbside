# Build image for the kerbside-proxy Rust crate. Kept deliberately minimal:
#   - build-essential + pkg-config: standard native build toolchain.
#   - git: required to fetch the shakenfist-spice-protocol git dependency.
#   - ca-certificates: TLS trust for the git fetch and crates.io.
# The rustls `ring` provider needs no OpenSSL or cmake, and protoc is vendored
# via the protoc-bin-vendored build-dependency, so no protobuf package is
# needed. Source is mounted at run time (see the Makefile), not COPYed in.
FROM rust:slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# rustfmt and clippy ship with the official image, but add them explicitly so
# `make lint` works regardless of the base image's component set (idempotent).
RUN rustup component add rustfmt clippy
