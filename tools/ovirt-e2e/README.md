# ovirt-e2e: oVirt end-to-end kerbside lane

This directory holds the runner-side driver scripts for the oVirt half of
the two-tier CI story (`.github/workflows/functional-tests.yml`'s
`ovirt_matrix` job). See
`docs/plans/PLAN-two-tier-ci-phase-01-ovirt-kerbside.md` for the full spec.

Unlike the `direct-qemu` lane (which fakes a cloud with a `type: static`
source and a local qemu) and unlike `sf-e2e` (which co-locates kerbside on
the Shaken Fist primary, the same shape as its console source), this lane
runs kerbside **on the CI runner**, off-box from oVirt, and proves the
`type: ovirt` source driver against a real oVirt 4.5 engine. Before this
lane existed, the `ovirt_matrix` job tested that the oVirt environment
still installs and that its SPICE console still answers a raw handshake
**on the target** -- it never deployed kerbside, never ran
`kerbside/sources/ovirt.py`, and never sent a byte of SPICE through the
Rust proxy.

## Topology

- oVirt engine and hypervisor are co-located on one Rocky 8 instance,
  reachable at `10.0.2.2` / FQDN `ovirt.local`. This is the existing
  single-node oVirt environment the target-side steps build; this lane
  changes nothing about it.
- kerbside (REST API on `13002`, SPICE proxy on `5900`/`5901`, MariaDB)
  runs on the CI runner, as plain processes, via
  `tools/direct-qemu/start-kerbside.sh`.
- ryll also runs on the runner, driving kerbside's proxy over localhost.

kerbside cannot live on the oVirt node: `pyproject.toml` sets
`requires-python = ">=3.11"`, and that node is Rocky 8 with a Python 3.6
system interpreter. Getting 3.11, MariaDB, and a `mysqlclient` build
environment onto it would be substantial work whose only purpose is to
avoid a network hop the lane actually wants to exercise. The runner
reaches `10.0.2.2` directly because `shakenfist/actions`'
`kerbside-single-node.yml` attaches it to the `10.0.2.0/24` test network
as part of building the environment.

Ports are confusing in logs and this is not a conflict: kerbside's
client-facing proxy binds `5900`/`5901` on the **runner** (`127.0.0.1`),
while the hypervisor's SPICE ports are `5900`/`5901` on **`10.0.2.2`**.
Different hosts, same port numbers.

## The path being proven

```
ryll --headless
  -> kerbside proxy        127.0.0.1:5901  (plaintext)
                           127.0.0.1:5900  (TLS, proxy CA)
  -> hypervisor            10.0.2.2:5900   -> NEED_SECURED
  -> hypervisor            10.0.2.2:5901   TLS: verified
                           against the engine CA, subject
                           pinned to O=local,CN=ovirt.local
  -> qemu on the oVirt host, authenticated with a fresh
     engine-issued graphics-console ticket
```

Everything on the right of the first arrow is code that, before this
lane, had never run in CI.

## Step flow

After the existing target-side environment build and the target-side
console checks, the workflow:

1. Resolves `ovirt.local` on the runner (`10.0.2.2 ovirt.local` appended
   to `/etc/hosts`) -- the engine's HTTPS certificate is `CN=ovirt.local`
   and `requests` verifies it against the CA, so an IP URL fails.
2. Probes `10.0.2.2:5900` and `:5901` from the runner and fails with an
   explicit firewall-pointing message if either is unreachable, so a
   network problem shows up as one line instead of an opaque TLS failure
   deep inside the drive step.
3. Builds the PR's kerbside-proxy wheel (the same manylinux build the
   `openstack_matrix` job uses) and builds ryll from source into
   `/usr/local/bin/ryll`, **without** `--features digest-decode` -- this
   lane's guest is a Debian 12 GNOME image with `spice-vdagent`
   pre-installed, not Uncalibrated Sextant, so the visual-digest feature
   has nothing to check.
4. Runs `deploy-kerbside.sh`, which installs build prerequisites, creates
   the `kerbside` MariaDB database (`tools/direct-qemu/setup-mariadb.sh`),
   builds a venv containing the PR's kerbside plus the PR's proxy wheel
   plus `ovirt-engine-sdk-python`, generates proxy TLS
   (`tools/direct-qemu/generate-tls.sh`), writes `sources.yaml`
   (`gen-sources.py`), starts kerbside by reusing
   `tools/direct-qemu/start-kerbside.sh` unchanged, writes
   `kerbside.env` for the driver, and polls until the `type: ovirt`
   source reaches a non-errored state.
5. Runs `drive-console.py`, which waits for the oVirt scrape to discover
   the lane's test VM, mints an API JWT from the auth seed, fetches the
   proxied `.vv` and launches `ryll --headless` against it immediately,
   asserts real SPICE surfaces and a screenshot via
   `tools/direct-qemu/smoke-client.py`, asserts a session and audit row
   exist, then terminates the console via the REST API and asserts the
   session and its termination audit event.

The three scripts:

- `gen-sources.py` -- writes a single-element `sources.yaml` with one
  `type: ovirt` source. Fetches the engine's CA certificate from
  `<engine-url>/services/pki-resource?resource=ca-certificate&
  format=X509-PEM-CA` (unverified -- this is the bootstrap fetch) and
  embeds it inline, so kerbside's own re-fetch-and-compare CA check
  passes by construction. Never echoes the password; writes the file
  0600.
- `deploy-kerbside.sh` -- runs entirely locally (no SSH); installs and
  starts kerbside on the runner, pointed at the engine, and writes
  `kerbside.env` for the driver. Never echoes the engine password, the
  auth seed, or key material.
- `drive-console.py` -- drives the actual proxied SPICE session and the
  DB/API assertions described above. Never prints the API JWT, the
  oVirt graphics-console ticket, the auth seed, or the `.vv` body.

## Configuration details that bite

These are traps found while reading `kerbside/sources/ovirt.py`; encode
them, do not re-derive them:

1. **The source `url` carries no `/api` suffix.**
   `oVirtSource._ensure_connection` appends `/api` itself, and the CA
   check appends `/services/pki-resource?...`. The correct value is
   `https://ovirt.local/ovirt-engine`. This differs from the URL the
   target-side test scripts use (`.../ovirt-engine/api`), which is right
   for them and wrong for `sources.yaml`.
2. **`ca_cert` is inline PEM text, compared for equality.**
   `oVirtSource.__init__` writes it to a temp file, re-fetches the
   engine's own copy from the `pki-resource` endpoint (this time
   verified against what we wrote), and marks the source errored unless
   the two match after `rstrip()`. `gen-sources.py` therefore fetches the
   CA from that exact URL rather than copying
   `/etc/pki/ovirt-engine/ca.pem` around, so the bytes match by
   construction.
3. **The runner must resolve `ovirt.local`.** The engine's certificate is
   `CN=ovirt.local`; an IP-only URL fails `requests`' verification. The
   backend SPICE leg needs no DNS entry -- the engine reports the console
   address as the IP `10.0.2.2`.
4. **`ovirt-engine-sdk-python` is deliberately not a kerbside
   dependency.** It is commented out in `pyproject.toml`, and
   `ovirt.py` imports it lazily, erroring the source if it is absent, so
   `deploy-kerbside.sh` installs it explicitly into the venv. It is a C
   extension, so the runner also needs `libxml2-dev`,
   `libcurl4-openssl-dev`, and `build-essential`.
5. **oVirt graphics-console tickets live for about 120 seconds** and are
   minted fresh on every `.vv` request. `drive-console.py` fetches the
   `.vv` and launches `ryll --headless` immediately, with nothing in
   between -- no sleep, no retry loop, no extra work.

## Security

No script in this directory logs or emits the engine password, the auth
seed, the API JWT, the oVirt graphics-console ticket, or the `.vv` body.
`sources.yaml` holds the engine password and is written 0600 by
`gen-sources.py`; it is deliberately NOT uploaded as a CI artifact, along
with `console.vv` and the auth seed file. The kerbside daemon log, the
gunicorn logs, ryll's stdio, and the smoke-client log are uploaded
instead -- an errored source or a failed relay is fully diagnosable from
those without ever needing the secret files.

## Env-file contract

`${WORKDIR}/kerbside.env` (default `WORKDIR=/tmp/kerbside-ovirt-ci`),
written by `deploy-kerbside.sh` and read by `drive-console.py`:

- `KERBSIDE_VENV` -- the venv containing kerbside, the proxy wheel,
  gunicorn, and the oVirt SDK.
- `KERBSIDE_SRC` -- the kerbside checkout that was installed (for
  reusing `tools/direct-qemu/smoke-client.py`).
- `KERBSIDE_WORKDIR` -- the lane's work directory (logs, TLS material,
  the console socket and screenshot land here).
- `KERBSIDE_SQL_URL` -- the MariaDB connection string kerbside was
  started with.
- `KERBSIDE_SOURCE_NAME` -- the `type: ovirt` source name in
  `sources.yaml`.
- `KERBSIDE_SOURCES_PATH` -- path to the generated `sources.yaml`.
- `KERBSIDE_API_PORT` -- the kerbside REST API port.
- `KERBSIDE_SEED_FILE` -- path to the auth seed used to mint API JWTs.
- `KERBSIDE_LOG_PATH` -- the kerbside daemon log (gunicorn logs sit
  alongside it with `.gunicorn-access` / `.gunicorn-error` suffixes).
- `RYLL_BIN` -- path to the ryll binary built for the lane.
- `OVIRT_ENGINE_URL` -- the engine URL the source was registered with
  (no `/api` suffix).

Deliberately absent: the engine password. The driver never needs it, and
this file lands in the run's artifacts.

See `docs/plans/PLAN-two-tier-ci-phase-01-ovirt-kerbside.md` for the
architecture decision, the full configuration-trap list, and the risks
considered before choosing to run kerbside on the runner.
