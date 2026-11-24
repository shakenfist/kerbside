# The kerbside demo stack

A working kerbside in three containers, so you can see what it does
before deciding whether to deploy it.

Nothing but docker is needed — specifically Docker Engine 23.0 or
newer with the Compose v2 plugin, so `docker compose` rather than
`docker-compose`. The image build uses `RUN --mount`, which needs
BuildKit, and BuildKit is the default builder from 23.0 on.

Debian 12 is the trap worth naming: `apt install docker.io
docker-compose` there gets you Engine 20.10.24, too old for
`RUN --mount`, and the end-of-life Python Compose v1, which provides no
`docker compose` subcommand at all, so the build fails with a message
that does not explain itself. Debian 13 fixed both halves — it ships
Engine 26.1.5 and packages Compose 2.26.1 as a real `docker compose`
plugin, so the distribution packages do work there. Installing from
[Docker's own repository](https://docs.docker.com/engine/install/debian/)
is still what Docker's own instructions assume and what kerbside's CI
does, and it is the one answer that works on every Debian.

```bash
docker compose up -d      # build and start; the first build takes a few minutes
./get-console.sh          # mint a token and write demo-console.vv
remote-viewer ./demo-console.vv
```

**Expect a black screen with BIOS text.** The demo VM has no disk, so
it tries a network boot, gives up, and SeaBIOS reports `No bootable
device`. That screen *is* the SPICE session: it is being drawn by a
real qemu, relayed through kerbside, over TLS. If you see it,
everything worked.

When you are finished:

```bash
docker compose down -v    # removes the containers, the database, the
                          # generated CA and the signing seed
```

## What is running

| Service | What it is |
|---|---|
| `db` | MariaDB. Kerbside's schema is created by `kerbside db upgrade` at startup. |
| `spice-target` | A disk-less qemu with a SPICE server. The thing being proxied. |
| `kerbside` | The REST API under gunicorn, and the SPICE proxy daemon. |

`docker compose logs -f kerbside` shows both kerbside processes.
The web UI is on <http://127.0.0.1:13002>, though you cannot log into
it — see "About that token" below.

## Things worth knowing

**The ports are bound to loopback on purpose.** `127.0.0.1:13002`,
`127.0.0.1:5900` and `127.0.0.1:5901` are published, and nothing is
reachable from your network. This demo has no real authentication, so
binding it more widely would put an unauthenticated console proxy in
front of a VM. If you change it, that is what you are accepting.

**Two processes in one container is not a shape to copy.** Running
the REST API and the SPICE proxy daemon under one entrypoint is the
shortest way to a working demo. A real deployment runs them as
separate units, and they need not share a host: the API reaches the
daemon only through the database. Only the daemon and the Rust proxy
it launches share a unix socket (`API_SOCKET_PATH`), and
`docs/configuration.md` covers that constraint.

**The TLS is genuine, and `get-console.sh` proves it rather than
assuming it.** The proxy leg uses TLS on port 5900 with a self-signed
CA generated into a volume at first start. You do not install that CA
anywhere: kerbside embeds it in the `.vv`, along with the certificate
subject to expect, and `remote-viewer` verifies against it.

Before printing the `remote-viewer` command, the script connects to
the port the `.vv` advertises, verifies the presented certificate
against the CA embedded in that same `.vv`, and checks the subject
matches. That is deliberately stronger than checking the `.vv` has the
right fields in it: kerbside writes `tls-port=` and `ca=`
unconditionally, so their presence says nothing about whether the TLS
listener works. A session quietly running over the plaintext port
while the TLS leg is broken looks identical to one that works, which
is the failure worth catching.

**The backend leg is not TLS**, deliberately. Kerbside talks plaintext
SPICE to the qemu container on the compose network. A second TLS leg
would add a failure mode you cannot see. Real deployments should pin
the backend too; `docs/use-cases/ovirt.md` covers that.

**Everything generated is per-deployment.** The CA and the JWT signing
seed are created on first start, not baked into the image, and
`down -v` destroys them. Shipping a known signing key is exactly the
problem described in issue #131.

## About that token

`get-console.sh` mints a bearer token by running `kerbside demo token`
inside the container. That is a demonstration affordance standing in
for authentication, not the intended user journey: interactive login is
Keystone-only today (issue #300), and the session JWT scheme has no
revocation or issuance audit (issue #301).

The command defends itself, and the refusals are worth trusting rather
than working around. It will not mint if any configured source is not
`static`, and it will not mint while the signing seed is still
unconfigured. If it refuses, something about the stack is genuinely
wrong.

Three things about its shape are deliberate:

- **It lives in a `demo` command group** rather than being, say,
  `kerbside token issue`. Where the command sits is what labels it
  demonstration-only, so the label cannot be diluted by a warning
  string being reworded, or by a serious-sounding command being added
  beside it later.
- **The static-only check is whole-deployment, not per source.** A
  session token is not scoped to a source: the API checks its signature
  and expiry and nothing else, so a token minted "for the static source"
  would open every console of every source. It reads `sources.yaml`
  rather than the database, because the database can hold rows from an
  earlier configuration, and a stale row blocking a legitimate demo is
  how a guard ends up growing a `--force` flag.
- **It writes no audit event**, only a warning to the log and to
  stderr. Kerbside's audit table is console-scoped, with the source and
  console UUID in its primary key, so a token issuance has nowhere to
  go. Issue #301 records that a real issuance audit needs a different
  event shape.

## Building against a checkout

The image installs the released `kerbside` from PyPI, so what you
evaluate is what you can install. That is the default and needs no
arguments. To build the checkout you are sitting in instead:

```bash
KERBSIDE_SOURCE=/src docker compose build kerbside
```

That form is what the CI lane uses, and it asks more of your
environment than the default does: it needs the repository's git
metadata in the build context, so it must be run from an ordinary
clone rather than a `git worktree`. `demo/Dockerfile` explains why,
and issue #326 tracks the underlying packaging fragility.

## If port 5900 is already taken

The demo publishes `127.0.0.1:5900`, the conventional VNC port, so a
desktop running a VNC server makes `docker compose up` fail with
`failed to bind host port 127.0.0.1:5900/tcp: address already in use`.
Docker does not say what holds the port; `sudo ss -tlnp 'sport = :5900'`
does.

If you remap it with a compose override file, note that compose merges
`ports` by appending, so an override listing different ports still
attempts the original bindings. Replacing the list needs the
`!override` tag (Compose 2.24 or newer). The proxy also writes its
port into the `.vv`, so a remapped host port needs
`KERBSIDE_PUBLIC_SECURE_PORT` and `KERBSIDE_PUBLIC_INSECURE_PORT` set
to match. Issue #750 tracks making this a single setting.

## Why it is built this way

**Compose, rather than the direct-qemu harness.**
`tools/direct-qemu/` already brings up MariaDB, TLS, a static source
and a real qemu on one host, and CI runs it on every pull request, so
it would have been a demo for free. It is a CI harness, though, with
CI's assumptions built in: it starts the host's MariaDB with systemd,
opens up `/dev/kvm`, installs packages into the host, uses fixed
`/tmp` paths, and builds ryll with a Rust toolchain. Pointing an
evaluator at it asks them to make their machine look like a GitHub
runner. The cost of compose is that the demo is new deployment
artefacts rather than documentation, which is why it has a CI lane of
its own (`demo-compose.yml`, see `docs/testing.md`).

**A real qemu, and no guest image.** A demo proxying a fake SPICE
server proves nothing, so `spice-target` is a real qemu. Fetching or
building a guest image (Uncalibrated Sextant is the project's test
guest) would give it something more interesting to show, at the price
of exactly the friction the demo exists to remove; the firmware screen
of a disk-less VM is a genuine SPICE display surface.

## Where to go next

[`docs/installation.md`](../docs/installation.md) is the narrative
version: what a real deployment needs, and how to get there from here.
