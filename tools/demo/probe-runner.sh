#!/bin/bash
# Probe a CI runner for what the compose demo lane needs.
#
# This exists because the demo lane is the FIRST container build in
# kerbside CI -- `grep -rn docker .github/workflows/` finds nothing else
# -- so nothing in the tree establishes that these runners can build
# images at all. Rather than discover that from a red lane whose failure
# could be any of a dozen things, this answers it in one cheap step.
#
# Follows tools/direct-qemu/probe-runner.sh: print diagnostics freely,
# exit non-zero only on a hard blocker. The hard blockers here are a
# missing or unreachable Docker daemon, a daemon older than 23.0, and a
# build that cannot reach a package index. Everything else is
# informational, including a port collision -- that one is reported
# rather than fatal because the demo can still be built and inspected
# on a runner whose ports are busy, and the operator needs to be told
# which port and not left with the Docker daemon's own bind error,
# which never names the holder.

set -uo pipefail

FAILED=0

fail() {
    echo "ERROR: $*" >&2
    FAILED=1
}

echo "=== docker client and daemon ==="
if ! command -v docker > /dev/null 2>&1; then
    fail "docker is not installed on this runner"
    echo ""
    echo "=== probe-runner cannot continue without docker ==="
    exit 1
fi
command -v docker
docker version || fail "the docker daemon is not reachable as $(id -un)"

# 23.0 is not a rounded-up guess: demo/Dockerfile uses
# `RUN --mount=type=bind`, which needs BuildKit, and 23.0 is the release
# where BuildKit became the default builder. The Dockerfile deliberately
# carries no `# syntax=` directive precisely so that no external
# frontend image is fetched, which means the built-in frontend has to be
# new enough on its own.
echo ""
echo "=== docker server version is at least 23.0 ==="
SERVER_VERSION="$(docker version --format '{{.Server.Version}}' 2> /dev/null)"
if [ -z "${SERVER_VERSION}" ]; then
    fail "could not read the docker server version; is the daemon running?"
else
    echo "server version: ${SERVER_VERSION}"
    SERVER_MAJOR="${SERVER_VERSION%%.*}"
    if [ "${SERVER_MAJOR}" -lt 23 ] 2> /dev/null; then
        fail "docker server ${SERVER_VERSION} is older than 23.0, so the built-in BuildKit frontend cannot parse RUN --mount in demo/Dockerfile"
    fi
fi

echo ""
echo "=== docker compose plugin ==="
# `docker compose`, not `docker-compose`: demo/README.md documents the v2
# plugin form, and the demo's compose file uses features the standalone
# python implementation never gained.
docker compose version || fail "the docker compose v2 plugin is not available"

echo ""
echo "=== ports the demo publishes ==="
# The demo publishes 13002, 5900 and 5901 on loopback. A collision here
# fails the stack at `up` time with the daemon's own message, which says
# only "address already in use" and never what holds it -- so name the
# holder now while it is cheap to look. 5900 is the realistic risk: it
# is the default VNC port and any desktop or screen-sharing service on
# the runner will have taken it.
for port in 13002 5900 5901; do
    if command -v ss > /dev/null 2>&1; then
        HOLDER="$(ss -tlnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p {print; exit}')"
    else
        HOLDER="$(netstat -tlnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p {print; exit}')"
    fi
    if [ -n "${HOLDER}" ]; then
        echo "WARNING: port ${port} is already bound; the demo stack will fail to start"
        echo "  ${HOLDER}"
    else
        echo "port ${port}: free"
    fi
done

echo ""
echo "=== a build container can reach a package index ==="
# The question the rest of this script exists for. The runners sit
# behind a squid proxy exported as http_proxy/https_proxy, and
# functional-tests.yml points pip at a devpi mirror through
# PIP_INDEX_URL. A `docker build` inherits NEITHER: not the proxy
# variables, not the index URL. So a demo image build reaching PyPI is
# a genuinely separate question from the runner reaching PyPI, and this
# is the cheapest honest test of it -- a real build, doing a real index
# lookup, in the same way demo/Dockerfile will.
#
# --no-deps and a download rather than an install: this is testing
# reachability, not resolution, and it should stay fast.
PROBE_DIR="$(mktemp -d)"
trap 'rm -rf "${PROBE_DIR}"' EXIT

cat > "${PROBE_DIR}/Dockerfile" <<'PROBE_EOF'
FROM python:3.13-slim
RUN pip download --no-deps --dest /tmp/probe kerbside-proxy \
    && ls -la /tmp/probe
PROBE_EOF

if docker build --no-cache --progress plain -t kerbside-demo-probe \
        "${PROBE_DIR}" 2>&1 | sed 's/^/  /'; then
    echo "index reachable from inside a build"
    docker rmi -f kerbside-demo-probe > /dev/null 2>&1 || true
else
    fail "a build container could not reach a package index; the demo image cannot be built on this runner without proxy or index configuration passed into the build"
fi

echo ""
echo "=== disk space ==="
# A python:3.13-slim base, a debian:trixie-slim base with qemu, a
# mariadb image and the build layers. Informational: if the lane starts
# failing on space this is the number to look at first.
df -h / /var/lib/docker 2> /dev/null || df -h /

echo ""
if [ "${FAILED}" -ne 0 ]; then
    echo "=== probe-runner FAILED: see the ERROR lines above ==="
    exit 1
fi
echo "=== probe-runner complete: this runner can build and run the demo ==="
