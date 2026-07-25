# sf-e2e: full Shaken Fist end-to-end lane

This directory holds the primary-side driver scripts for the **phase 9**
Shaken Fist end-to-end CI lane (`.github/workflows/sf-e2e-functional.yml`).
See `docs/plans/PLAN-kerbside-vdi-tokens-phase-09-e2e.md` for the full spec.

Unlike the `direct-qemu` lane (which fakes a cloud with a `type: static`
source and a local qemu), this lane stands up a **real single-node Shaken
Fist** and drives the joined flow that no earlier phase could:

    SF mints an Ed25519 JWT
      -> kerbside verifies it OFFLINE against keys SF actually published
      -> kerbside exchanges it for a consoletoken + .vv
      -> ryll drives a proxied SPICE session against the Sextant guest
         booted INSIDE the SF instance.

## Topology

Everything runs **co-located on the SF primary node** (the
`build-smoke-cluster` primary), as plain processes, exactly as the
`direct-qemu` lane runs kerbside via `start-kerbside.sh`:

- Shaken Fist API: `http://localhost:13000` (env in `/etc/sf/sfrc`;
  `sf-ctl` / `sf-client` at `/srv/shakenfist/venv/bin/`).
- Kerbside REST API (gunicorn): `http://127.0.0.1:13002`.
- Kerbside SPICE proxy: `PUBLIC_FQDN=127.0.0.1`, ports `5900` (secure) /
  `5901` (insecure).
- MariaDB: the primary's existing MariaDB; this lane creates a `kerbside`
  db/user (`mysql://kerbside:kerbside@127.0.0.1/kerbside`).
- ryll: built from source with `--features digest-decode`, installed to
  `/usr/local/bin/ryll`, driving kerbside's proxy over localhost.

## The audience / URL contract (must match byte-for-byte)

`KERBSIDE_URL` is set in the SF cluster config **and** is the token `aud`
claim **and** the exchange-URL base. Kerbside's
`SF_CONSOLE_TOKEN_AUDIENCE` must equal it exactly. This lane uses:

    KERBSIDE_URL = http://127.0.0.1:13002
    KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE = http://127.0.0.1:13002

## Step flow

The composite action `shakenfist/actions/deploy-kerbside-on-shakenfist`
copies this checkout + the proxy wheel to the primary and runs:

1. `provision-sf.sh <KERBSIDE_URL> <TOKEN_DURATION>` — sets `KERBSIDE_URL`
   and `KERBSIDE_TOKEN_DURATION` in the SF cluster, ensures a signing key,
   restarts `sf-api`, and waits for the API to answer.
2. `deploy-kerbside.sh` — creates the `kerbside` MariaDB db/user, builds
   ryll from source, creates a venv, installs kerbside + the proxy wheel +
   `shakenfist_client`, generates proxy TLS, writes `sources.yaml` (via
   `gen-sources.py`), and starts kerbside by reusing
   `../direct-qemu/start-kerbside.sh` (exporting
   `KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE` first). It writes
   `/tmp/sf-e2e/kerbside.env` describing the deployment for the drivers.

Then the workflow runs, over SSH:

3. `import-instance.sh` — creates namespace `vdie2e`, uploads the Sextant
   qcow2 as a shared image, and boots a UEFI + SPICE instance from it.
   Emits `/tmp/sf-e2e/instance.env`.
4. `drive-happy-path.py` — waits for kerbside's scrape to pick up the
   console, mints + exchanges the token (one client call returns the
   `.vv`), drives a proxied SPICE session with `ryll --headless`, reuses
   `../direct-qemu/smoke-client.py` (surfaces + screenshot) and
   `../direct-qemu/wait-for-banner.sh` (Sextant boot banner via SF console
   data), asserts a session audit row exists, and that terminating the
   console removes the session.
5. `drive-adversarial.py` — five asserted rejections against the live app:
   replay, expired, wrong audience, unknown kid, and a cross-namespace
   mint attempt.

## Security

No script logs or serves the raw token string or any private key
material. The auth seed and generated keys are written with `600`
permissions and are never emitted to stdout or artifacts. Public keys are
fine to log.

## Env-file contract

- `/tmp/sf-e2e/kerbside.env` (written by `deploy-kerbside.sh`): venv path,
  `KERBSIDE_SQL_URL`, audience, source name, workdir, API port, auth-seed
  path, sources path, ryll binary.
- `/tmp/sf-e2e/instance.env` (written by `import-instance.sh`): instance
  uuid, namespace, namespace key, SF API URL.
