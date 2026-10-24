# ── Stage 1: Build ryll from upstream main ───────────────────────────────────
# No rust-toolchain.toml in the ryll repo, so the rust image tag is what
# pins the toolchain.  It tracks trixie like the stage 2 runtime below.
# Clone from main HEAD — no pinned ref, by design: ryll cuts no release
# tags to pin to, and pinning a commit is worth its upkeep only once an
# unpinned build has failed to reproduce.
FROM rust:1.97-trixie AS builder

# System build dependencies required by the ryll workspace:
#   pkg-config    — locates system libs for build scripts
#   cmake         — needed by reqwest → aws-lc-sys (TLS)
#   libasound2-dev — ALSA headers for cpal (audio)
#   libxcb-*-dev, libx11-dev, libxkbcommon-dev — X11/XCB for eframe/egui
#   libgl1-mesa-dev, libegl1-mesa-dev — OpenGL for eframe
#   libwayland-dev — Wayland backend for egui-winit
#   libssl-dev    — OpenSSL headers for tokio-rustls / reqwest
#   git, ca-certificates — clone from GitHub
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    git \
    libasound2-dev \
    libegl1-mesa-dev \
    libgl1-mesa-dev \
    libssl-dev \
    libwayland-dev \
    libx11-dev \
    libxcb-render0-dev \
    libxcb-shape0-dev \
    libxcb-xfixes0-dev \
    libxcb1-dev \
    libxkbcommon-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/shakenfist/ryll.git /src

WORKDIR /src

# Build the ryll binary (package name "ryll" in the workspace).
# The ryll crate has no headless feature flag; it builds a single binary
# that supports --headless, --web, and GUI modes.  Default features
# include "capture" (pcap/mp4 recording); disable them for a lighter
# binary since the loadtest never uses capture mode.
RUN cargo build --release --no-default-features -p ryll

# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM debian:trixie AS runtime

# Python 3 + pip, OpenStack client tools, jq/wget for the
# makeconsole.sh provisioning logic, and the system shared
# libraries that the ryll binary links against at runtime.
#
# `cargo build --no-default-features -p ryll` does not link
# eframe/egui-winit/cpal/opus-decoder: those sit behind ryll's `gui`
# and `audio` Cargo features (both default-on; both opted out by the
# stage-1 build above).  So the runtime image needs none of the
# GUI/audio shared libraries -- libasound2, libgl1, libx11-6, libxcb1,
# libxkbcommon0, libwayland-client0.  libssl3 stays (still needed by
# tokio-rustls / reqwest).
RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends \
    git \
    jq \
    libssl3 \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv

# Install OpenStack client libraries from source (same approach as
# the original single-stage Dockerfile).
RUN git clone https://github.com/openstack/openstacksdk /srv/openstacksdk
RUN git clone https://github.com/openstack/python-openstackclient \
    /srv/python-openstackclient

RUN pip install --break-system-packages bindep yq

RUN cd /srv/openstacksdk && pip install --break-system-packages -e .
RUN cd /srv/python-openstackclient && pip install --break-system-packages -e .

# Install kerbside (the package under test / metric consumer).
ADD . /srv/kerbside
RUN cd /srv/kerbside && apt-get install -y $(bindep --brief) || true
RUN cd /srv/kerbside && pip install --break-system-packages -e .

# Ryll binary from stage 1.
COPY --from=builder /src/target/release/ryll /usr/local/bin/ryll

# Orchestrator and shell scripts.
COPY loadtests/latency/orchestrator.py /srv/orchestrator.py
ADD loadtests/latency/makeconsole.sh /srv/makeconsole.sh
ADD loadtests/latency/cleanupconsoles.sh /srv/cleanupconsoles.sh

CMD ["/srv/makeconsole.sh"]
