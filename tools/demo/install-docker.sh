#!/bin/bash
# Install Docker Engine and the compose v2 plugin on a private-CI runner.
#
# The demo lane is the first container build in kerbside CI, and the
# runner image has no docker at all: tools/demo/probe-runner.sh reported
# `docker is not installed on this runner` on
# [self-hosted, vm, debian-12, l].
#
# Debian 12 cannot supply what the demo needs either, which is why this
# uses Docker's own apt repository rather than the distribution's:
#
#   - bookworm ships docker.io 20.10.24, below the 23.0 that
#     demo/Dockerfile's `RUN --mount=type=bind` needs from the built-in
#     BuildKit frontend (see probe-runner.sh for why the Dockerfile
#     cannot just carry a `# syntax=` directive instead);
#   - bookworm has no docker-compose-v2 package at all. Its only compose
#     is 1.29.2, the end-of-life python implementation, which does not
#     provide the `docker compose` subcommand the demo documents.
#
# That is also the install path demo/README.md points a human at, so the
# lane and the documentation stay the same story.
#
# Idempotent on purpose. If the runner image ever grows a new enough
# docker this becomes a no-op, and the lane stops paying for it without
# anyone having to remember to delete the step.
#
# Verifying the result is NOT this script's job. It installs and
# configures; tools/demo/probe-runner.sh then independently checks that
# the daemon is reachable, new enough, and that a build can reach a
# package index.

set -euo pipefail

# 23.0 and the compose plugin are the same two requirements
# probe-runner.sh enforces. Checked here as well so that a runner which
# already has them is not reinstalled over.
have_usable_docker() {
    command -v docker > /dev/null 2>&1 || return 1
    local version
    version="$(docker version --format '{{.Server.Version}}' 2> /dev/null)"
    [ -n "${version}" ] || return 1
    [ "${version%%.*}" -ge 23 ] 2> /dev/null || return 1
    docker compose version > /dev/null 2>&1 || return 1
}

if have_usable_docker; then
    echo "=== docker is already usable, nothing to install ==="
    docker version --format 'server {{.Server.Version}}'
    docker compose version
    exit 0
fi

echo "=== installing docker from download.docker.com ==="
sudo apt-get update
sudo apt-get install -y --no-install-recommends ca-certificates curl

sudo install -m 0755 -d /etc/apt/keyrings

# curl runs unprivileged and pipes into `sudo tee`, rather than the
# `sudo curl -o` the upstream instructions use. sudo resets the
# environment, so a privileged curl loses the runner's http_proxy and
# cannot reach download.docker.com through the squid in front of it.
curl -fsSL https://download.docker.com/linux/debian/gpg \
    | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc

ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc]" \
    "https://download.docker.com/linux/debian ${CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

# Two separate proxy problems, and neither is solved by the runner's own
# environment variables.
#
# The daemon is a system service: it inherits nothing from the job, so
# without a drop-in it cannot pull a base image from Docker Hub through
# squid. The CLI is the second: it does not pass the job's proxy
# variables into a build either, and ~/.docker/config.json is the
# documented way to make it do so, which demo/Dockerfile's pip step
# needs. probe-runner.sh checks that pip step independently, so if a
# runner turns out to have direct egress this whole block can go.
if [ -n "${http_proxy:-}" ] || [ -n "${https_proxy:-}" ]; then
    echo ""
    echo "=== configuring the daemon and builds to use the runner proxy ==="
    NO_PROXY_VALUE="${no_proxy:-127.0.0.1,localhost}"

    DROPIN="$(mktemp)"
    {
        echo '[Service]'
        if [ -n "${http_proxy:-}" ]; then
            echo "Environment=\"HTTP_PROXY=${http_proxy}\""
        fi
        if [ -n "${https_proxy:-}" ]; then
            echo "Environment=\"HTTPS_PROXY=${https_proxy}\""
        fi
        echo "Environment=\"NO_PROXY=${NO_PROXY_VALUE}\""
    } > "${DROPIN}"

    sudo mkdir -p /etc/systemd/system/docker.service.d
    sudo install -m 0644 "${DROPIN}" \
        /etc/systemd/system/docker.service.d/http-proxy.conf
    rm -f "${DROPIN}"

    echo "daemon drop-in:"
    sed 's/^/  /' < /etc/systemd/system/docker.service.d/http-proxy.conf

    sudo systemctl daemon-reload
    sudo systemctl restart docker

    # Merged rather than written, so that a pre-existing registry login
    # on the runner is not discarded along with it.
    mkdir -p "${HOME}/.docker"
    HTTP_PROXY_VALUE="${http_proxy:-}" \
    HTTPS_PROXY_VALUE="${https_proxy:-}" \
    NO_PROXY_VALUE="${NO_PROXY_VALUE}" \
        python3 - <<'PYTHON'
import json
import os
import pathlib

path = pathlib.Path(os.environ['HOME']) / '.docker' / 'config.json'
config = json.loads(path.read_text()) if path.exists() else {}

default = config.setdefault('proxies', {}).setdefault('default', {})
for key, name in (('httpProxy', 'HTTP_PROXY_VALUE'),
                  ('httpsProxy', 'HTTPS_PROXY_VALUE'),
                  ('noProxy', 'NO_PROXY_VALUE')):
    value = os.environ.get(name, '')
    if value:
        default[key] = value

path.write_text(json.dumps(config, indent=2) + '\n')
print('build proxies in %s:' % path)
print('\n'.join('  ' + line for line in json.dumps(default, indent=2).splitlines()))
PYTHON
else
    echo ""
    echo "=== no http_proxy in the environment, leaving proxy config alone ==="
fi

# The same idiom as direct-qemu-functional.yml's `sudo chmod a+rw
# /dev/kvm`. Adding the runner user to the docker group is the tidier
# fix, but group membership only takes effect on a new login and a
# workflow step cannot get one. These are single-tenant per-job VMs, so
# widening the socket for the life of the job is proportionate.
echo ""
echo "=== granting the runner user access to the docker socket ==="
sudo chmod a+rw /var/run/docker.sock

echo ""
echo "=== installed ==="
docker version --format 'client {{.Client.Version}} / server {{.Server.Version}}'
docker compose version
