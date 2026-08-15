# The kerbside demo image: the REST API and the SPICE proxy daemon.
#
# The build context is the REPOSITORY ROOT, not demo/. The image needs
# tools/direct-qemu/generate-tls.sh, and KERBSIDE_SOURCE=/src needs the
# checkout; docker-compose.yml sets `context: ..` accordingly.

FROM python:3.13-slim

# The Debian package set is taken from bindep.txt rather than guessed.
# It exists because mysqlclient ships no wheel: every install builds it
# from source, and from 2.2.0 it locates libmysqlclient with pkg-config
# rather than the mysql_config binary, so pkg-config and the MariaDB
# client headers both have to be here. openssl and curl are runtime
# needs of entrypoint.sh and get-console.sh.
#
# Everything stays in one stage, build dependencies included. A
# multi-stage build would be smaller, but mysqlclient links against
# libmariadb at runtime, so the split has to be done carefully to stay
# correct -- not a trade worth making in a demo whose value is being
# readable.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        libmariadb-dev-compat \
        libxml2-dev \
        libxslt1-dev \
        locales \
        openssl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Where kerbside comes from.
#
# The default is the checkout, NOT the released package, and that is a
# reversal of what this phase originally planned. The plan wanted the
# default to be `kerbside` from PyPI, on the reasoning that a demo
# silently testing unreleased code works for the maintainer and fails
# for everyone else. That reasoning is right and the default is still
# wrong today, for a blunt reason: entrypoint.sh runs
# `kerbside db upgrade`, which was added by phase 1 of this plan and
# has not been released. The newest release is 0.4.0, and
# `kerbside db upgrade` in a 0.4.0 image fails with
# "Error: No such command 'db'".
#
# So the choice is between a demo that works and a demo that installs
# the released package, and it is not a close call. Flip this default
# back to `kerbside` in the first release that carries `kerbside db
# upgrade`; nothing else here needs to change, and phase 5's
# documentation should describe the released form.
#
#   docker compose build --build-arg KERBSIDE_SOURCE=kerbside
#
# kerbside-proxy is installed explicitly because a checkout install
# does not bring it. The pin is inserted into pyproject.toml at release
# time by tools/stamp-proxy-version.sh and is deliberately absent from
# the committed tree (see the KERBSIDE_PROXY_PIN marker there), so
# there is nothing in /src for pip to resolve. Taking the released
# proxy wheel rather than building Rust here is safe and checked, not
# assumed: the only change to kerbside/rpc/kerbside.proto between
# v0.4.0 and develop is a comment, so the daemon and the released proxy
# speak an identical gRPC contract. Verify that still holds before
# trusting it again:
#
#   git diff v<latest>..develop -- kerbside/rpc/kerbside.proto
#
# If the contract ever does move ahead of a release, the demo has to
# build the proxy wheel with tools/build-proxy-wheel.sh instead.
# Installing both in one pip invocation lets pip resolve them together,
# so setting KERBSIDE_SOURCE=kerbside stays correct: the release pin
# and this line agree rather than fighting.
#
# The bind mount is read-write so pip can build in-tree without the
# checkout needing to be writable on the host; the overlay is discarded
# when the step finishes, so nothing is written back and no copy of the
# source is baked into the image.
ARG KERBSIDE_SOURCE=/src
RUN --mount=type=bind,source=.,target=/src,rw \
    pip install --no-cache-dir kerbside-proxy "${KERBSIDE_SOURCE}"

# One TLS bootstrap in the tree, and it is the CI-proven one. Copied
# rather than reimplemented so the demo and the direct-qemu lane cannot
# drift into producing different certificates.
COPY tools/direct-qemu/generate-tls.sh \
     /usr/local/lib/kerbside-demo/generate-tls.sh
COPY demo/demo-env.sh /usr/local/lib/kerbside-demo/demo-env.sh
COPY demo/entrypoint.sh /usr/local/bin/kerbside-demo-entrypoint
# On PATH so `docker compose exec kerbside kerbside-demo-env ...` works:
# exec does not inherit what the entrypoint exported, so anything run
# that way needs the generated seed and certificate paths put back.
COPY demo/kerbside-demo-env /usr/local/bin/kerbside-demo-env
RUN chmod +x /usr/local/lib/kerbside-demo/generate-tls.sh \
             /usr/local/bin/kerbside-demo-entrypoint \
             /usr/local/bin/kerbside-demo-env

# Generated TLS material and the signing seed live here, on a named
# volume, so they survive `compose restart` but not `compose down -v`.
VOLUME /var/lib/kerbside-demo

EXPOSE 13002 5900 5901

ENTRYPOINT ["/usr/local/bin/kerbside-demo-entrypoint"]
