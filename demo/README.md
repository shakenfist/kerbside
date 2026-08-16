# The kerbside demo stack

A working kerbside in three containers, so you can see what it does
before deciding whether to deploy it.

Nothing but docker is needed — specifically Docker Engine 23.0 or
newer with the Compose v2 plugin, so `docker compose` rather than
`docker-compose`. The image build uses `RUN --mount`, which needs
BuildKit, and BuildKit is the default builder from 23.0 on.

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

**Two processes in one container is not a shape to copy.** The REST
API and the SPICE proxy daemon share a unix socket
(`API_SOCKET_PATH`), so they must be co-located, and running both under
one entrypoint is the shortest way to get there for a demo. A real
deployment runs them as separate units or containers sharing that
socket. `docs/configuration.md` covers the constraint.

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

## Building against a checkout

The image installs kerbside from the checkout you are sitting in.
That is the default and needs no arguments. To build against the
released PyPI package instead:

```bash
KERBSIDE_SOURCE=kerbside docker compose build kerbside
```

The default *should* be the released package — a demo that silently
tests unreleased code works for the maintainer and fails for everyone
else. It is not, yet, because `kerbside db upgrade` is newer than the
current release and the entrypoint needs it. `demo/Dockerfile` has the
detail and says when to flip it back.

## Where to go next

[`docs/installation.md`](../docs/installation.md) is the narrative
version: what a real deployment needs, and how to get there from here.
