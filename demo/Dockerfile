# The kerbside demo image: the REST API and the SPICE proxy daemon.
#
# The build context is the REPOSITORY ROOT, not demo/. The image needs
# tools/direct-qemu/generate-tls.sh, and a KERBSIDE_SOURCE=/src build
# needs the checkout; docker-compose.yml sets `context: ..`
# accordingly. .dockerignore keeps build artefacts out of that context.
#
# Requires Docker Engine 23.0 or newer, where BuildKit is the default
# builder: the pip step below uses `RUN --mount=type=bind`, which the
# classic builder cannot parse. There is deliberately no
# `# syntax=docker/dockerfile:1` directive -- it would work, but it
# makes every build fetch an external frontend image from Docker Hub,
# and the built-in frontend in Docker 23+ already supports everything
# used here. demo/README.md states the version requirement.

FROM python:3.13-slim

# The Debian package set is taken from bindep.txt rather than guessed.
# It exists because mysqlclient ships no wheel: every install builds it
# from source, and from 2.2.0 it locates libmysqlclient with pkg-config
# rather than the mysql_config binary, so pkg-config and the MariaDB
# client headers both have to be here. openssl and curl are runtime
# needs of entrypoint.sh and get-console.sh.
#
# git is here for KERBSIDE_SOURCE=/src builds only, and it is not an
# obvious requirement: setuptools_scm shells out to git for both the
# version and the file list, so without the binary a checkout install
# fails with "setuptools-scm was unable to detect version" even when
# .git is right there in the context. The default PyPI build does not
# need it, but installing it unconditionally keeps one image serving
# both paths -- the alternative is a build arg that changes the apt
# list, which is a lot of machinery for one small package.
#
# Everything stays in one stage, build dependencies included. A
# multi-stage build would be smaller, but mysqlclient links against
# libmariadb at runtime, so the split has to be done carefully to stay
# correct -- not a trade worth making in a demo whose value is being
# readable.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        libmariadb-dev-compat \
        libxml2-dev \
        libxslt1-dev \
        locales \
        openssl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Where kerbside comes from.
#
# The default is the released package from PyPI, so what you evaluate
# is what you can install. A demo that silently tests unreleased code
# works for the maintainer and fails for everyone else.
#
# The other value this takes is `/src`, the checkout mounted below,
# which is what the CI lane uses: a lane exercising the PyPI default
# would test the last release rather than the pull request.
#
#   KERBSIDE_SOURCE=/src docker compose build kerbside
#
# kerbside-proxy is named explicitly, but it is belt and braces rather
# than load-bearing: pyproject.toml carries a dev-inclusive floor
# (`kerbside-proxy>=0.4.0.dev0`, at the KERBSIDE_PROXY_PIN marker), so
# either KERBSIDE_SOURCE resolves a proxy wheel on its own. The exact
# `==` pin only appears in a released sdist, inserted by
# tools/stamp-proxy-version.sh; the committed tree deliberately holds
# the floor instead.
#
# What each path gets differs, and it matters. The PyPI default takes
# the matching release, because a released kerbside pins
# kerbside-proxy==<its own version>. A /src build takes whatever the
# floor allows, and `.dev0` in that floor makes pre-releases eligible,
# so it takes the newest *dev* wheel published from develop by
# dev-proxy-wheel.yml. That is the right pairing for a checkout: the
# daemon and the binary both track develop.
#
# The two only disagree while a proto change is unreleased and no dev
# wheel has been published for it yet. That fails loudly rather than
# subtly -- phase 3 of PLAN-proxy-dev-releases added a proto-hash
# handshake, and proxy_supervisor.check_contract() refuses to launch a
# binary whose hash differs or which cannot answer --contract-hash at
# all. Confirm the pairing directly when in doubt:
#
#   git diff v<latest>..develop -- kerbside/rpc/kerbside.proto
#
# The bind mount is read-write so pip can build in-tree without the
# checkout needing to be writable on the host; the overlay is discarded
# when the step finishes, so nothing is written back and no copy of the
# source is baked into the image.
#
# A /src build needs real git metadata in the context, and that is a
# sharper requirement than it looks.
#
# setuptools_scm does two jobs for a checkout install. It derives the
# version, and -- via its git file finder -- it is the only reason
# kerbside/sources/ and kerbside/migrations/ end up installed at all:
# neither directory has an __init__.py, so neither appears in
# pyproject.toml's `packages` list, and setuptools' own discovery never
# sees them. Without git the install succeeds and then dies at import
# with "No module named 'kerbside.sources'".
#
# Two consequences worth knowing before editing this:
#
#   * .dockerignore must not exclude .git.
#   * Building from a git *worktree* does not work, because there .git
#     is a file pointing at a directory outside the build context.
#     Build from an ordinary clone.
#
# Both apply to KERBSIDE_SOURCE=/src only; the default build never
# looks at the checkout and is happy in a worktree. This fragility is
# not the demo's, it is the packaging's, and it still bites anyone
# pip-installing kerbside from a git URL. Filed as issue #326.
ARG KERBSIDE_SOURCE=kerbside
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
