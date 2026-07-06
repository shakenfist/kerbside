# kerbside-proxy build targets.
#
# Rust builds are wrapped in Docker (matching the operator's preference and
# the ryll cargo-cache mount pattern). The crate lives at rust/kerbside-proxy/
# but build.rs and the shakenfist-spice-protocol git dependency both reference
# ../../kerbside/rpc/kerbside.proto, so the container MUST see the whole repo.
# We therefore mount the REPO ROOT at /repo and set the workdir to the crate
# inside it (/repo/rust/kerbside-proxy) -- mounting only the crate dir would
# leave ../../kerbside/rpc unresolved and the build would fail.
#
# The cargo registry + git caches are mounted from .cargo-cache/ so repeated
# builds do not re-download crates. NOTE: `make build` needs network access on
# the first run to fetch crates.io and the ryll git dependency.

IMAGE := kerbside-proxy-dev
REPO_ROOT := $(abspath $(CURDIR)/../..)
CRATE_DIR := rust/kerbside-proxy
CARGO_CACHE := $(CURDIR)/.cargo-cache
UID := $(shell id -u)
GID := $(shell id -g)

# The official rust image makes /usr/local/cargo world-writable, so running
# as an arbitrary host UID/GID and writing into the mounted cache works.
DOCKER_RUN = docker run --rm \
	-v "$(REPO_ROOT)":/repo \
	-v "$(CARGO_CACHE)/registry":/usr/local/cargo/registry \
	-v "$(CARGO_CACHE)/git":/usr/local/cargo/git \
	-w /repo/$(CRATE_DIR) \
	-u $(UID):$(GID) \
	-e HOME=/tmp \
	$(IMAGE)

.PHONY: all image cache build test lint clean help

all: build

help:
	@echo "kerbside-proxy build targets:"
	@echo "  make image  - Build the kerbside-proxy-dev Docker image"
	@echo "  make build  - Build the crate (debug) in the container"
	@echo "  make test   - Run the test suite in the container"
	@echo "  make lint   - Run rustfmt --check and clippy -D warnings"
	@echo "  make clean  - Remove target/ and the cargo cache"

image:
	docker build -t $(IMAGE) .

$(CARGO_CACHE)/registry $(CARGO_CACHE)/git:
	mkdir -p $@

cache: $(CARGO_CACHE)/registry $(CARGO_CACHE)/git

build: image cache
	$(DOCKER_RUN) cargo build

test: image cache
	$(DOCKER_RUN) cargo test

lint: image cache
	$(DOCKER_RUN) sh -c "cargo fmt --all --check && cargo clippy --all-targets -- -D warnings"

clean:
	rm -rf target $(CARGO_CACHE)
