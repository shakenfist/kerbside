# quic-bench build targets.
#
# Rust builds are wrapped in Docker, like the proxy's, and reuse the proxy's
# kerbside-proxy-dev image rather than defining a second one -- this crate
# needs nothing the proxy's image does not already carry. The image is built
# by rust/kerbside-proxy/Makefile, which owns its Dockerfile; the `image`
# target here just delegates there.
#
# The repo root is mounted at /repo and the workdir is this directory inside
# it, matching the proxy's pattern. This crate has no path dependency outside
# itself, but mounting the root keeps the two invocations the same shape and
# lets the binary land at a predictable place on the host.
#
# The cargo registry and git caches are mounted from .cargo-cache/ so repeated
# builds do not re-download crates. The first `make release` needs network
# access to fetch crates.io.

IMAGE := kerbside-proxy-dev
REPO_ROOT := $(abspath $(CURDIR)/../..)
CRATE_DIR := tools/quic-bench
CARGO_CACHE := $(CURDIR)/.cargo-cache
UID := $(shell id -u)
GID := $(shell id -g)

DOCKER_RUN = docker run --rm \
	-v "$(REPO_ROOT)":/repo \
	-v "$(CARGO_CACHE)/registry":/usr/local/cargo/registry \
	-v "$(CARGO_CACHE)/git":/usr/local/cargo/git \
	-w /repo/$(CRATE_DIR) \
	-u $(UID):$(GID) \
	-e HOME=/tmp \
	$(IMAGE)

.PHONY: all image cache build release test lint clean help

all: release

help:
	@echo "quic-bench build targets:"
	@echo "  make image   - Build the shared kerbside-proxy-dev Docker image"
	@echo "  make build   - Build the bench (debug) in the container"
	@echo "  make release - Build the bench (release) in the container"
	@echo "  make test    - Run the test suite in the container"
	@echo "  make lint    - Run rustfmt --check and clippy -D warnings"
	@echo "  make clean   - Remove target/ and the cargo cache"
	@echo "Then run tools/quic-bench/run-bench.sh, which shapes the link."

image:
	$(MAKE) -C $(REPO_ROOT)/rust/kerbside-proxy image

$(CARGO_CACHE)/registry $(CARGO_CACHE)/git:
	mkdir -p $@

cache: $(CARGO_CACHE)/registry $(CARGO_CACHE)/git

build: image cache
	$(DOCKER_RUN) cargo build

release: image cache
	$(DOCKER_RUN) cargo build --release

test: image cache
	$(DOCKER_RUN) cargo test

lint: image cache
	$(DOCKER_RUN) sh -c "cargo fmt --all --check && cargo clippy --all-targets -- -D warnings"

clean:
	rm -rf target $(CARGO_CACHE)
