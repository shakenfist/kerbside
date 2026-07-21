# Kerbside VDI tokens phase 7: functional tests and CI

This is phase 7 of a **cross-repository master plan** whose plan of record
lives in the Shaken Fist repository
(`shakenfist/docs/plans/PLAN-kerbside-vdi-tokens.md`, branch
`vdi-console-tokens`). It spans **two repos**: a Shaken Fist mint-path
functional test (`shakenfist-wt-vdi-tokens`, branch `vdi-console-tokens`)
and a kerbside offline exchange + proxy end-to-end lane
(`kerbside-wt-vdi-tokens`, branch `sf-vdi-tokens`).

## Scope decision (why this is smaller than the master plan's phase 7)

The master plan's phase 7 originally bundled a **full cross-repo
end-to-end** test: deploy a real single-node Shaken Fist, have the client
mint a token via `/vdiconsoleproxy`, exchange it at a real kerbside, and
drive a proxied SPICE session. That path **cannot go green before the
PRs merge**: kerbside CI installs Shaken Fist and the client at each
repo's `develop` HEAD (there is no per-PR SHA pinning — the actions repo
comment literally says "we're just going to have to land things in the
right order"), so the loop is red until the SF and client changes reach
`develop`. Making it green pre-merge would require branch-injection
surgery into the external `shakenfist/actions` CI repo.

Per the maintainer's decision, that full-loop test is **pulled out of
phase 7 into its own later phase (phase 9)**, run once the four PRs are on
`develop`. Phase 7 keeps only what is **greenable pre-merge**:

- **7a (SF):** the minting path is self-contained in Shaken Fist — a
  functional test can mint and verify the JWT against the published
  public key with no kerbside involved.
- **7b (kerbside):** the `/sf-console.vv` exchange is **offline by
  design** (Ed25519 signature check against DB-cached keys), so it can be
  exercised end to end — through the real proxy — by seeding a keypair,
  with no Shaken Fist involved.

The phase-5 adversarial cases (replay, expired, wrong audience, unknown
kid, unscraped console) are already covered by unit tests
(`test_sf_token.py`, `test_api.py::SfTokenApiTestCase`); 7b re-asserts them
against the live Flask app + real MariaDB as a regression backstop.

## Situation (grounded)

### Shaken Fist side

- Functional ("cluster") tests live in
  `shakenfist/deploy/shakenfist_ci/cluster_ci_tests/` and run against a
  **real deployed cluster** via the actions reusable workflow
  `smoke-cluster.yml`, driven through the REST API by the
  `shakenfist_client` SDK. The shared fixture is
  `deploy/shakenfist_ci/base.py`: `BaseTestCase` builds an admin
  `system_client`; `BaseNamespacedTestCase` (`base.py:761`) builds a
  scoped `self.test_client` via `_make_namespace(name, key)` (`base.py:75`).
  Cross-namespace pattern to copy: `test_object_names.py:90`
  (`test_instance_same_name_different_namespace`) makes a second scoped
  client and asserts per-namespace isolation.
- The endpoints under test:
  `InstanceVDIProxyConsoleHelperEndpoint` (`external_api/instance.py:1497`,
  route `/instances/<ref>/vdiconsoleproxy`, `app.py:358`) — mints via
  `vdi_tokens.mint_console_token(..., audience=config.KERBSIDE_URL,
  issuer=config.ZONE, duration=config.KERBSIDE_TOKEN_DURATION)`, returns
  `{url, expires_at}`, 404s if `KERBSIDE_URL` unset, 406 if not
  `created`, 409 if not a SPICE console; and
  `AdminVDITokenPublicKeyEndpoint` (`external_api/admin.py:80`, route
  `/admin/vditokenpubkey`, `app.py:266`) — returns
  `vdi_tokens.public_view(material)` (`{kid, alg, public_pem}` list) to any
  authenticated token.
- **The client SDK at `develop` has no method for either endpoint** (only
  `get_vdi_console_helper`); those methods live on the unmerged phase-4
  branch. So the functional test must call `client._request_url('GET',
  '/instances/<uuid>/vdiconsoleproxy')` and `.../admin/vditokenpubkey`
  **directly**, not via a client method — this is what keeps 7a
  independent of the client PR's merge order.
- Provisioning `KERBSIDE_URL` + a signing key: `sf-ctl` exposes a
  cluster-config setter (`client/ctl.py:236`, `mariadb.set_cluster_config`)
  and `ensure-kerbside-signing-key` (`client/ctl.py:283`). `KERBSIDE_URL`
  is seeded cluster-wide the same way `DNS_SERVER` is (per the phase-2
  plan). Empty `KERBSIDE_URL` = feature off (the endpoint 404s).

### kerbside side

- `direct-qemu-functional.yml` is a cloud-free lane that boots a real
  qemu SPICE backend, starts kerbside (REST API + Rust proxy), and drives
  a proxied SPICE session. `tools/direct-qemu/lane-up.sh` writes a
  `type: static` `sources.yaml` with source `direct-qemu-lab` and console
  uuid `6f4e2c1a-0000-0000-0000-000000000001` (`lane-up.sh:22-23,50-60`),
  then mints a **kerbside** HS256 auth JWT with PyJWT and fetches the
  `.vv` (`lane-up.sh:118-178`). `start-kerbside.sh` sets the `KERBSIDE_*`
  env (`start-kerbside.sh:57-83`), including `KERBSIDE_PUBLIC_FQDN=127.0.0.1`;
  it does **not** set `KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE`, so
  `sf_token.expected_audience()` (`sf_token.py:59`) derives
  `https://127.0.0.1`.
- The exchange endpoint is `GET /sf-console.vv?token=<jwt>` (`api.py:648`,
  `api.py:845`). It verifies the token offline
  (`sf_token.verify_sf_token`), rejects a replayed `jti`, then looks up the
  scraped console with `db.get_console(claims['source'], claims['sub'])`
  and asserts the row's source matches, else 404. Keys are cached per
  source in `sf_token_keys` via `db.upsert_sf_token_keys(source, keys_json,
  fetched_at)` (`db.py:852`); jtis in `sf_token_jtis`. The exact EdDSA
  mint shape (header `kid`, claims `aud/sub/sf:namespace/iat/exp/jti`) is
  in `tests/unit/test_sf_token.py` — mirror it.

## Decisions

1. **7a calls `_request_url` directly, not a client method.** Keeps the SF
   functional test green at `develop` HEAD regardless of the client PR.
2. **7a provisions `KERBSIDE_URL` + signing key the SF-repo-local way.**
   Prefer the deploy path that seeds `DNS_SERVER` (a collection/CI config
   value in the SF repo) so the cluster comes up with `KERBSIDE_URL` set
   and a signing key ensured. If no clean deploy hook exists, fall back to
   ensuring both in the test's `setUp` via `sf-ctl` on the primary
   (the suite runs there with admin `sfrc`), and `self.skipTest(...)` if
   the feature is unconfigured — never a hard failure that would also
   break clusters that legitimately run the feature off.
3. **7b seeds an Ed25519 keypair and mints locally; no Shaken Fist.** The
   exchange is offline, so a generated key published into
   `sf_token_keys[direct-qemu-lab]` plus a PyJWT-minted EdDSA token
   (sub = the static console uuid, aud = the audience kerbside expects)
   drives the real `/sf-console.vv` path end to end.
4. **7b pins the audience deterministically.** Add
   `export KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE='https://kerbside-ci.example'`
   to `start-kerbside.sh` and mint with that exact `aud`, rather than
   coupling the check script to `PUBLIC_FQDN`.
5. **Full cross-repo e2e is out of scope → phase 9** (see the master
   plan). Phase 7 adds no `shakenfist/actions` changes.

## Execution

Sub-agents where mechanical; the token-minting/verification code is
correctness-critical and reviewed against the real endpoints. The two
repos are independent — 7a and 7b share no artifact.

### Shaken Fist side (worktree `shakenfist-wt-vdi-tokens`, branch `vdi-console-tokens`)

| Step | Effort | Model | Brief |
|------|--------|-------|-------|
| A1 | medium | opus | New `deploy/shakenfist_ci/cluster_ci_tests/test_vdi_tokens.py`: `class TestVDIConsoleTokens(base.BaseNamespacedTestCase)` with `namespace_prefix='vditokens'`. Create a `created` SPICE instance (video vdi=spice; follow the instance-create pattern in a sibling cluster test, minimal disk, `_await_instance_ready`). **Happy path:** `resp = self.test_client._request_url('GET', '/instances/%s/vdiconsoleproxy' % uuid).json()`; assert `resp['url']` starts with `<KERBSIDE_URL>/sf-console.vv?token=` and `resp['expires_at']` is in the future; extract the token; fetch `/admin/vditokenpubkey`; decode the token **unverified** to read `aud`+`kid`, then `jwt.decode(token, public_pem_for_kid, algorithms=['EdDSA'], audience=aud)` and assert `sub==uuid`, `iss==zone`, the namespace claim == this namespace, `jti` present, and `aud` equals the URL's origin. **Ownership:** a second scoped client (namespace B) requesting namespace A's instance raises the not-authorised/not-found client exception (mirror `test_object_names.py`). Optionally a non-SPICE instance → 409. Attach debug context with `self.addDetail`. |
| A2 | low | sonnet | Provisioning (decision 2): make the CI cluster come up with `KERBSIDE_URL` set to a sentinel (e.g. `https://kerbside-ci.example`) and a signing key ensured, mirroring how `DNS_SERVER` is seeded for CI. Keep it SF-repo-local; if it must live in the test, ensure it in `setUp` via `sf-ctl` and `skipTest` when unconfigured. No `shakenfist/actions` change. |

### kerbside side (worktree `kerbside-wt-vdi-tokens`, branch `sf-vdi-tokens`)

| Step | Effort | Model | Brief |
|------|--------|-------|-------|
| K1 | low | sonnet | In `tools/direct-qemu/start-kerbside.sh`, `export KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE='https://kerbside-ci.example'` alongside the other `KERBSIDE_*` env (decision 4), so the daemon and the check script agree on the audience. |
| K2 | high | opus | New `tools/direct-qemu/run-sf-token-checks.sh` (standalone, mirrors `run-host-subject-checks.sh`), run while the main lane is up. It: (a) generates an Ed25519 keypair with `cryptography`; (b) publishes it into `sf_token_keys` for source `direct-qemu-lab` via `db.upsert_sf_token_keys(source, json.dumps({active_kid, keys:[{kid, alg:'EdDSA', public_pem}]}), time.time())` (run under the same `KERBSIDE_SQL_URL`); (c) mints an EdDSA token (header `kid`; claims `iss`, `aud='https://kerbside-ci.example'`, `sub=<CONSOLE_UUID>`, `sf:namespace`, `iat`, `exp`, `jti`) mirroring `test_sf_token.py`; (d) `GET /sf-console.vv?token=...` → assert 200 and a `.vv` body carrying a password line; (e) **connect through the proxy** with that `.vv` (reuse `smoke-client.py`/the ryll control socket, or a minimal TLS SPICE handshake against the proxy port) to prove the exchanged token yields a working proxied session. **Adversarial** (same running kerbside, pure HTTP): replay the same token → 401 `token already used`; expired `exp` → 401; `aud='https://evil'` → 401; unseeded `kid` → 401; valid token but `sub=<random uuid>` → 404. Every assertion checks the HTTP status; the token is never echoed to logs. |
| K3 | low | sonnet | Wire `run-sf-token-checks.sh` into `direct-qemu-functional.yml` as a step after the main scenario and before `lane-down` (needs the API up and the console scraped), and upload its log as an artifact (mirror the host-subject-checks step's `upload-artifact` block). |

## Success criteria

* Shaken Fist: a namespaced client mints a `/vdiconsoleproxy` token whose
  signature verifies against `/admin/vditokenpubkey`, with correct
  `sub`/`iss`/`aud`/namespace/`exp`; a foreign namespace cannot mint for
  another's instance. Runs green on the existing functional matrix with no
  kerbside and no client-PR dependency.
* kerbside: a locally-minted Shaken Fist token is exchanged at the real
  `/sf-console.vv` for a `.vv` that drives a working proxied SPICE
  session, and every adversarial variant is refused with its specific
  status — all in the cloud-free `direct-qemu` lane, no Shaken Fist.
* No private key material or token string is logged. `tox` stays green in
  both repos; no `shakenfist/actions` change.

## Dependencies and out of scope

* **Out of scope → phase 9:** the full cross-repo end-to-end (real
  single-node Shaken Fist → client mint → kerbside exchange → proxied
  session), including any `shakenfist/actions` branch-injection needed to
  run it pre-merge. It lands after the four PRs are on `develop`.
* **Out of scope → phase 8:** operator/user docs for the whole flow.
* 7a and 7b are independent and can land in either order on their
  respective branches.
