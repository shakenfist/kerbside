# sf-e2e: full Shaken Fist end-to-end lane

This directory holds the deploy profile and the scripts for the Shaken
Fist end-to-end CI lane (`.github/workflows/sf-e2e-functional.yml`).

Unlike the `direct-qemu` lane (which fakes a cloud with a `type: static`
source and a local qemu), this lane stands up a **real single-node Shaken
Fist** and drives the joined flow end to end:

    SF mints an Ed25519 JWT
      -> kerbside verifies it OFFLINE against keys SF actually published
      -> kerbside exchanges it for a consoletoken + .vv
      -> ryll drives a proxied SPICE session against the Sextant guest
         booted INSIDE the SF instance.

## Topology

Everything runs **co-located on the SF primary node** (the
`build-smoke-cluster` primary, on its single-node `localhost` topology).
Kerbside is deployed by the cluster deploy itself, through the
`shakenfist.kerbside` collection's `kerbside` role, as a real deployment
would deploy it:

- Shaken Fist API: `http://localhost:13000` (env in `/etc/sf/sfrc`;
  `sf-ctl` / `sf-client` at `/srv/shakenfist/venv/bin/`).
- Kerbside REST API: the `kerbside-api` systemd unit (gunicorn) on
  `http://127.0.0.1:13002`.
- Kerbside daemon and SPICE proxy: the `kerbside-daemon` systemd unit,
  `PUBLIC_FQDN=127.0.0.1`, ports `5900` (secure) / `5901` (insecure).
- Kerbside's venv, configuration and certificate: where the role puts
  them, `/srv/kerbside/venv` and `/etc/kerbside/` (`kerbside.ini`,
  `sources.yaml`, `pki/`).
- MariaDB: the primary's existing MariaDB; the deploy profile creates a
  `kerbside` db/user.
- ryll: built from source with `--features digest-decode`, installed to
  `/usr/local/bin/ryll`, driving kerbside's proxy over localhost.

## The audience / URL contract (must match byte-for-byte)

`KERBSIDE_URL` is set in the SF cluster config **and** is the token `aud`
claim **and** the exchange-URL base. Kerbside's
`SF_CONSOLE_TOKEN_AUDIENCE` must equal it exactly. The deploy profile
sets the one variable, `kerbside_url`, which the node role renders as
`KERBSIDE_URL` and the `kerbside` role as `sf_console_token_audience`:

    kerbside_url = http://127.0.0.1:13002

## Step flow

The workflow runs, in order:

1. `build-wheels.sh` — on the runner, builds this checkout's kerbside
   wheel and its manylinux kerbside-proxy wheel into
   `kerbside/dist/sf-e2e-wheels/`.
2. `shakenfist/actions/build-smoke-cluster`, with
   `deploy-profile.yml.j2` as its deploy profile. The profile puts the
   primary in a `kerbside` group, sets the Kerbside variables, creates
   the database, installs this checkout's `ansible/` collection, and
   hands the role the two wheels as `kerbside_local_wheels`. Shaken
   Fist's `site.yml` then deploys Shaken Fist (develop) and Kerbside
   (this pull request) together: the node role sets `KERBSIDE_URL`,
   mints the signing key and a dedicated `kerbside` system key, and the
   `kerbside` role installs, configures and starts Kerbside, and waits
   for its Shaken Fist source to fetch the signing keys. The cluster is
   deployed a second time, and no `sf-*` or `kerbside-*` unit may
   restart.
3. The checkout, less its git history and build output, is copied to
   the primary at `/tmp/sf-e2e/kerbside`, and
   `prepare-drivers.sh` builds ryll from source and writes
   `/tmp/sf-e2e/kerbside.env` from the configuration the role wrote.

Then, over SSH on the primary:

4. `import-instance.sh` — creates namespace `vdie2e`, uploads the Sextant
   qcow2 as a shared image, and boots a UEFI + SPICE instance from it.
   Emits `/tmp/sf-e2e/instance.env`.
5. `drive-happy-path.py` — waits for kerbside's scrape to pick up the
   console, mints + exchanges the token (one client call returns the
   `.vv`), drives a proxied SPICE session with `ryll --headless`, reuses
   `../direct-qemu/smoke-client.py` (surfaces + screenshot) and
   `../direct-qemu/wait-for-banner.sh` (Sextant boot banner via SF console
   data), asserts a session audit row exists, and that terminating the
   console removes the session.
6. `drive-adversarial.py` — five asserted rejections against the live app:
   replay, expired, wrong audience, unknown kid, and a cross-namespace
   mint attempt.

The drivers run as root (`sudo`), with the role's venv. They read the
role's `sources.yaml`, which only root and the `kerbside` group may
read, and the role's files keep the owners and modes it gave them.

## Security

No script logs or serves the raw token string or any private key
material. The copy of the auth seed the drivers read is written `0600`,
and neither it nor the role's configuration is ever emitted to stdout or
artifacts. Public keys are fine to log. Every credential in
`deploy-profile.yml.j2` is a throwaway value for a disposable CI cluster.

`gather-artifacts.sh` collects the ryll logs, the `.vv`, the Sextant
serial log, and the whole-run journals of Kerbside's units
(`kerbside.journal`), of every SF daemon (`sf-api.journal`,
`sf-console.journal`, `sf-daemons.journal`) and of libvirt
(`libvirtd.journal`). It never collects anything under `/etc/kerbside/`,
`kerbside.env` or the auth seed file. The journals can carry secrets: a
libvirt refusal echoes the domain XML, SPICE `passwd='...'` included,
and a database error can print the SQL URL with its password. So every
collected file is redacted in one pass over the output directory, and a
file in which a password-shaped value survives, as a key or in a URL, is
withheld from the upload and fails the step by name. See shakenfist/kerbside#482.

## Env-file contract

- `/tmp/sf-e2e/kerbside.env` (written `0600` by `prepare-drivers.sh`):
  venv path, checkout path, `KERBSIDE_SQL_URL`, audience, source name,
  workdir, API port, auth-seed path, sources path, ryll binary, SF API
  URL. The values come from the role's `kerbside.ini` and
  `sources.yaml`; the source name is the cluster's `deploy_name`. The
  auth seed is copied to a root-owned `0600` file in the workdir, since
  the happy path reads it from a file.
- `/tmp/sf-e2e/instance.env` (written by `import-instance.sh`): instance
  uuid, namespace, namespace key, SF API URL.
