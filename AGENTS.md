# AI Agent Guidelines for Kerbside

This document provides guidance for AI agents (like Claude) working on the
Kerbside codebase.

## Project Overview

Kerbside is a SPICE VDI protocol proxy that enables remote console access to
VMs across multiple cloud platforms (Shaken Fist, OpenStack, oVirt). It handles
SPICE protocol negotiation, authentication, and bidirectional traffic relay.

## Key Files to Understand

| File | Purpose |
|------|---------|
| `kerbside/api.py` | REST API endpoints and web UI |
| `kerbside/db.py` | Database models (Source, Console, ConsoleToken, ProxyChannel, AuditEvent) |
| `kerbside/main.py` | Daemon entry point and maintenance loop |
| `kerbside/config.py` | Pydantic-based configuration |
| `kerbside/rpc/kerbside.proto` | KerbsideProxy gRPC contract fronting the DB for the proxy |
| `kerbside/rpc/servicer.py` | gRPC servicer implementing the contract against db.py |
| `kerbside/rpc/server.py` | serve()/stop() hosting the servicer over a unix socket in the daemon |
| `rust/kerbside-proxy/` | The SPICE proxy (start here for connection handling): TLS termination, handshake, gRPC-authorised inspection-first relay that enforces an L0+L1 SPICE firewall. Builds in Docker via its Makefile |
| `rust/kerbside-proxy/src/policy.rs` | The `Policy`/`Verdict` seam and the firewall engine: `FirewallPolicy` (tunable knobs), `EnforcementMode` (Enforce/WarnOnly), `EnforcingPolicy` (L0 size/rate caps + L1 allowlist lookup), `VerdictTally` (coalesced per-connection audit) |
| `rust/kerbside-proxy/src/allowlist.rs` | The compiled-in L1 message-type grammar: `classify(channel, dir, msg_type) -> Allowed \| Disallowed \| ChannelUnmodeled`, derived from the ryll `shakenfist-spice-protocol` name tables |
| `kerbside/proxy_supervisor.py` | Launches/supervises the Rust `kerbside-proxy` binary as the daemon's child — `find_proxy_bin()` (env/PATH/dev-build resolution), `build_proxy_argv()` (config → CLI flags), `terminate_child()` (SIGTERM-then-SIGKILL with a deadline) |
| `kerbside/db.py` (`SessionTermination`, migration `c4e7a1b9d2f3`) | The `session_terminations` intent table (`request_session_termination`, `get_terminations_for_node`, `reap_session_terminations`) that bridges API-driven termination to each proxy node's local `ProxyControl` push — see "Session termination" below |
| `rust/kerbside-proxy/src/session.rs` (`SessionRegistry`) | The `session_id -> CancellationToken` registry the relay's `select!` and `ProxyControl`'s `TerminateSession` handler share, plus the shutdown-time `terminate_all()` drain |
| `kerbside/sources/static.py` | Static source driver: reads VM-to-console mapping from an inline list in sources.yaml; designed for CI pipelines and ad-hoc debugging (no control plane required) |

## Architecture Patterns

### SPICE proxy internals

The SPICE proxy is the Rust `kerbside-proxy` (`rust/kerbside-proxy/src/`):
it accepts connections, terminates TLS, drives the SPICE link handshake,
authorises each connection over the gRPC control socket, connects the
backend leg, and relays framed traffic as async tokio tasks (one per
connection) while enforcing the L0+L1 firewall. See `ARCHITECTURE.md`
(section 3) for the connection flow and supervision model, and
`docs/proxy-architecture.md` for the SPICE protocol and channel
background.

## Common Tasks

### Adding a New Source Type

1. Create a new file in `kerbside/sources/`
2. Inherit from `BaseSource` (see `sources/base.py`)
3. Implement `__call__()` to yield console entries
4. Register the source type in `main.py:_parse_sources()`

### Adding a New API Endpoint

1. Create a Flask-RESTful Resource class in `api.py`
2. Add the route in the `api.add_resource()` section
3. Use `@jwt_required()` decorator for authenticated endpoints
4. Return both HTML and JSON responses where appropriate

### Adding Database Migrations

```bash
cd /path/to/kerbside
alembic revision -m "description_of_changes"
# Edit the generated file in alembic/versions/
alembic upgrade head
```

### Changing the gRPC contract

The `KerbsideProxy` control-plane service is defined in
`kerbside/rpc/kerbside.proto`. After editing it, regenerate the
checked-in Python stubs (they are committed alongside the `.proto`):

```bash
tox -egenprotos   # runs tools/gen-protos.sh (grpc_tools.protoc + import fixups)
```

Implement RPC handlers in `kerbside/rpc/servicer.py`; the server is
hosted over a unix socket by `kerbside/rpc/server.py` (started from
`daemon_run`). Keep `grpcio`/`protobuf` (runtime) and
`grpcio-tools`/`mypy-protobuf` (tox genprotos deps) pinned in lockstep
so regeneration is deterministic.

### Building / working on the Rust proxy

The Rust SPICE proxy lives in `rust/kerbside-proxy/` (its own crate;
`.gitignore`d `target/`). Builds are wrapped in Docker (matching the
"don't install Rust toolchains on the host" preference) via the crate's
Makefile, which mounts the repo root so the crate can reach
`kerbside/rpc/kerbside.proto`:

```bash
make -C rust/kerbside-proxy build   # cargo build in the kerbside-proxy-dev image
make -C rust/kerbside-proxy test    # cargo test
make -C rust/kerbside-proxy lint    # cargo fmt --check + clippy -D warnings
```

`build.rs` generates the tonic gRPC client from the same
`kerbside/rpc/kerbside.proto` the Python side uses (vendored protoc, no
system protobuf needed). The generator is `tonic-prost-build` and the
generated stubs name types from `tonic` and `tonic-prost`, so those three
crates (plus `prost`) must be bumped together — a runtime crate that
moves without its code generator emits stubs that will not compile. The
`tonic-prost-rust` group in `renovate.json` keeps Renovate proposing them
as one PR. The crate depends on the ryll
`shakenfist-spice-protocol` crate as a git dependency pinned to a specific
rev in `Cargo.toml`; bump the `rev` (and commit the updated `Cargo.lock`)
when picking up ryll changes. CI runs fmt/clippy/test/build via
`.github/workflows/rust.yml`; end-to-end verification against qemu is
`docs/direct-qemu-harness.md`.

#### Packaging and release

The crate is published to PyPI as a separate `kerbside-proxy` package —
a maturin `bindings = "bin"` wheel (`rust/kerbside-proxy/pyproject.toml`)
that carries the compiled binary in the wheel's `*.data/scripts/` dir, so
`pip install` puts `kerbside-proxy` on `PATH` and `find_proxy_bin()`
resolves it via `shutil.which`. `kerbside` exact-pins
`kerbside-proxy`, and both release in lockstep from one `v*` tag:

- `tools/stamp-proxy-version.sh <version>` propagates the tag version into
  the crate's `Cargo.toml` `[package] version` (maturin reads it) and
  inserts the `kerbside-proxy==<version>` pin into `pyproject.toml` before
  the `# KERBSIDE_PROXY_PIN` marker. The committed tree carries no pin (the
  sibling is not on PyPI in a dev checkout — `find_proxy_bin()` uses the
  build tree / `KERBSIDE_PROXY_BIN` there).
- `tools/build-proxy-wheel.sh <x86_64|aarch64>` builds a manylinux_2_28
  wheel; aarch64 is cross-compiled from x86_64 with maturin `--zig`. No
  sdist is published (wheels only).
- `release.yml` runs the matrix build + publishes both packages
  (proxy first); `rust.yml` builds a wheel on PRs as a packaging guard.
  See `RELEASE-SETUP.md` for the two trusted publishers.

#### SPICE firewall

The relay enforces L0 (size caps, a disabled-by-default rate ceiling,
idle-read timeout, TCP keepalive) and L1 (per-channel/direction
message-type allowlist) firewall policy on every relayed message, on by
default. Python owns the tunable knobs and delivers them per-connection
over gRPC in the `AuthorizeConnection` reply; the L1 allowlist tables are
compiled into the proxy (they are a fact about the SPICE protocol, not
deployment policy). See `docs/proxy-architecture.md` (per-message
pipeline detail) and `docs/configuration.md` (the `FIREWALL_MODE` /
`FIREWALL_PERMITTED_CHANNELS` config knobs) for the full picture.

To validate the firewall against a real client without risking a broken
session, run the warn-only capture in `docs/direct-qemu-harness.md`: it
brings the mock gRPC server up delivering a `WARN_ONLY` `FirewallPolicy`,
drives a real SPICE client (remote-viewer/virt-viewer/ryll headless)
through the proxy, then asserts
`kerbside_proxy_firewall_verdicts_total` is entirely zero (a clean
capture) via `verify-rust-proxy.sh assert-firewall`. Any non-zero
`observed` verdict on legitimate traffic means the compiled allowlist or
a size cap needs widening — never the verdict weakening. The same harness
also has a deny-token/deny-all mode for exercising the
`PermissionDenied` denial path end to end.

#### Daemon supervision + session termination

`kerbside daemon run` supervises the Rust `kerbside-proxy` binary as a
child via `kerbside/proxy_supervisor.py`: it binds the gRPC UDS server
before launching the child (the proxy dials it at startup), polls child
liveness, and forwards SIGTERM with a 15-second deadline before
SIGKILLing — exiting non-zero if the child dies. The proxy binds its
`/metrics` server on its own `--metrics-address` (default loopback, config
`PROMETHEUS_METRICS_ADDRESS`) rather than the public VDI address.

API-driven session termination drops in-flight connections, not just new
ones. Because the REST API and proxy nodes may be on different machines
(and a load-balanced session's channels may span nodes), the only shared
bus is the database: `ConsolesTerminate`/`SessionTerminate` (`api.py`)
insert a `session_terminations` intent row; each node's daemon polls it
(scoped to sessions live on that node) in its `ProxyControl` handler
(`servicer.py`) and pushes `TerminateSession`; the proxy's
`SessionRegistry` (`session.rs`) cancels that session's shared
`CancellationToken`, and the relay's `select!` (`relay.rs`) tears every
channel down. A TTL reaper cleans up old intent rows; a merely-expired
token is never pushed, so natural expiry does not drop a live session.
See `docs/proxy-architecture.md` and `ARCHITECTURE.md` for the full flow
and the distributed-deployment rationale.

To validate live termination against a real client without a full
API+daemon+MariaDB stack, use the termination check in
`docs/direct-qemu-harness.md`:
the mock gRPC server's `ProxyControl` stream emits a one-shot
`TerminateSession` a configurable number of seconds after the first
authorization (`MOCK_GRPC_TERMINATE_AFTER`), standing in for the API/DB
leg so the harness exercises the proxy-side cancellation path live.

### Direct-qemu functional lane

`.github/workflows/direct-qemu-functional.yml` runs the smoke + banner +
Sextant scenario (`run-scenario.sh`) against the real daemon+API+MariaDB
stack with a headless ryll client through the Rust proxy. Its "Can
enqueue: direct-qemu" gate job is a required status check in the
develop ruleset (renaming it without updating the ruleset
blocks all merges), and the lane also runs nightly because the merge
queue does not re-run it against the merged tree. `start-kerbside.sh`
pre-checks the proxy binary via `find_proxy_bin()`, and the lane builds and
installs the `kerbside-proxy` wheel so it resolves on `PATH` as in a real
deployment. The lane also runs the live API-terminate test
(`verify-terminate-live.sh`) and a non-gating keypress-to-screen latency
loadtest (`run-loadtest.sh`), each on its own isolated lane before the
shared scenario lane.

The Rust leg additionally:

- Builds and installs the `kerbside-proxy` wheel into the kerbside venv
  (`install-proxy-wheel.sh` → `build-proxy-wheel.sh --native`), so
  `find_proxy_bin()` resolves it via `shutil.which` on `PATH` — the real
  install path, given CI coverage here.
- Runs `verify-terminate-live.sh` (Rust-only): on an isolated lane, calls
  the REST terminate endpoint and asserts the in-flight connection drops
  via the proxy log `session terminated by control plane`, exercising the
  DB→`ProxyControl` bridge end to end (not the mock).

Both legs run `run-loadtest.sh` (non-gating, `continue-on-error`): it
drives `loadtests/latency/orchestrator.py` to sample keypress-to-screen
latency (real `send_key` events timed against the `surface_drawn` they
produce) through the leg's proxy and records p50/p95 as an artifact; the
Python-vs-Rust comparison is read off the two legs. The loadtest boots the
purpose-built `tests/fixtures/uefi-latency-guest.qcow2` (which repaints on
every keypress) rather than the Sextant scenario fixture (which leaves its
Awaiting screen on the first key and freezes at the bootloader prompt). It
brings up its OWN isolated lane (separate WORKDIR, `QCOW2` overridden) and
tears it down before the scenario lane starts, exactly as
`verify-terminate-live.sh` does. This is distinct from the local mock
harness (`docs/direct-qemu-harness.md`), which needs no daemon or
database.

### Shaken Fist end-to-end lane (`sf-e2e`)

`.github/workflows/sf-e2e-functional.yml` (a pull_request smoke gate, plus
nightly schedule and manual dispatch) is the only lane that exercises the
`type: shakenfist` console source against a real cluster. Its "Can
enqueue: sf-e2e" gate job is a required status check in the develop
ruleset; renaming it without updating the ruleset blocks all merges. It
stands up a single-node Shaken Fist at develop HEAD
(`build-smoke-cluster`, topology `localhost`), then
`shakenfist/actions/deploy-kerbside-on-shakenfist`
provisions `KERBSIDE_URL` + a signing key in SF and deploys a co-located
kerbside (reusing `tools/direct-qemu/start-kerbside.sh`, with the SF token
audience exported). The primary-side drivers live in `tools/sf-e2e/`:
`provision-sf.sh`, `gen-sources.py`, `deploy-kerbside.sh`,
`import-instance.sh` (uploads the Sextant fixture, boots a UEFI+SPICE
instance), `drive-happy-path.py` (mint → offline verify → exchange →
proxied SPICE session, reusing `smoke-client.py` + `wait-for-banner.sh`,
then asserts a session audit row and clean teardown), and
`drive-adversarial.py` (replay, expired, wrong audience, unknown kid,
cross-namespace mint). `KERBSIDE_URL` and `SF_CONSOLE_TOKEN_AUDIENCE` must
match byte-for-byte (`http://127.0.0.1:13002`). No script logs the token or
key material. See `tools/sf-e2e/README.md`.

### oVirt end-to-end lane (`ovirt-e2e`)

`.github/workflows/functional-tests.yml`'s `ovirt_matrix` job is the only
lane that exercises the `type: ovirt` console source against a real oVirt
4.5 engine. Unlike `sf-e2e`, kerbside is NOT co-located with its source: the
oVirt target is Rocky 8 with a Python 3.6 system interpreter, below
`pyproject.toml`'s `requires-python = ">=3.11"` floor, so kerbside runs
off-box on the CI runner instead, reaching the engine at
`https://ovirt.local/ovirt-engine` and the hypervisor's SPICE ports at
`10.0.2.2:5900`/`5901` over the test network `kerbside-single-node.yml`
attaches the runner to. The runner-side drivers live in `tools/ovirt-e2e/`:
`gen-sources.py` (writes a `type: ovirt` `sources.yaml`, fetching the
engine's CA from its `pki-resource` endpoint so kerbside's re-fetch-and-
compare CA-equality check passes by construction), `deploy-kerbside.sh`
(installs and starts kerbside locally, reusing
`tools/direct-qemu/start-kerbside.sh`, and waits for the source to reach a
non-errored state), and `drive-console.py` (waits for the oVirt scrape to
discover the lane's test VM, mints an API JWT, fetches the proxied `.vv`
and launches `ryll --headless` against it immediately — oVirt
graphics-console tickets expire in ~120s — then asserts a real relayed
SPICE session via `smoke-client.py`, a session and audit row, and clean
teardown on terminate). See `tools/ovirt-e2e/README.md`. The
operator-facing version of what this lane proves — the front-door
architecture, the engine account, and the network prerequisites — is
`docs/use-cases/ovirt.md`.

The engine also carries `no-spice-test`, a diskless VNC-only VM created by
`tools/create-ovirt-vnc-vm.py` purely so discovery's skip-and-continue
branch runs somewhere. Every other VM in every lane has a SPICE display,
which is why a missing `continue` in `kerbside/sources/ovirt.py` went
unnoticed: it errored the source, truncated the scrape, and reaped the
surviving consoles as gone. `drive-console.py` asserts that VM is absent
from the console list. If you add a lane VM, think about which branch it
leaves untested.

Anything in that script that looks up an oVirt object by name must scope
the lookup to the `test` cluster or its datacenter. The lane runs two
datacenters and both have an `ovirtmgmt` network and vNIC profile of the
same name, so a bare name match silently picks whichever the engine lists
first and fails with a 409 only when it guesses wrong (issue #283). The
merge tier is the only place this code runs, so a smoke-green PR proves
nothing about it.

`drive-console.py` asserts against the proxy's log text, so it strips ANSI
before matching and keeps "the field would not parse" separate from "the
field was empty" — the first is a harness fault, the second is a real
unpinned TLS leg, and conflating them (issue #272) reported a broken parser
as a security failure for two days. Any new log-derived oracle should do the
same. Proxy log colouring is described in `docs/proxy-architecture.md`.

### Modifying SPICE Protocol Handling

SPICE wire-format parsing lives in the Rust proxy, which reuses the ryll
`shakenfist-spice-protocol` crate (`rust/kerbside-proxy/` depends on it by
git rev); the L1 firewall grammar is in `rust/kerbside-proxy/src/allowlist.rs`.

See the protocol documentation in `docs/` for detailed information:
- `docs/spice/protocol-overview.md` - SPICE protocol fundamentals
- `docs/spice/spice-link-protocol.md` - Connection handshake and authentication
- `docs/spice/channel-protocols.md` - Per-channel message formats
- `docs/spice/usb-redirection.md` - USB device redirection protocol
- `docs/proxy-architecture.md` - Kerbside proxy internals

External reference: https://www.spice-space.org/spice-protocol.html

## Testing

### Running Tests

```bash
# Unit tests
tox -e py3

# Style checks
tox -e pep8

# Check OS dependencies
tox -e bindep
```

### Test Locations

- Unit tests: `kerbside/tests/unit/`
- Functional tests: `kerbside/tests/functional/`
- Tempest plugin: `tempest-plugin/kerbside_tempest_plugin/` (separate
  releasable, driven via `tools/run-tempest-tests` and the
  `openstack_matrix` job in `.github/workflows/functional-tests.yml`)
  - `tests/api/test_spice_via_kerbside.py` — OpenStack lane only;
    requires a live cloud.
  - `tests/scenario/test_sextant_scenario.py` — direct-qemu lane;
    drives the full Sextant Awaiting → Parked sequence over Ryll's
    control socket, asserting the `digest_updated` event stream and
    the post-mortem serial drain. Skips when
    `CONF.kerbside.control_socket_path` is unset (OpenStack lane
    safety). Requires ryll built with `--features digest-decode`.
    Configured via the `[kerbside]` tempest options:
    `control_socket_path`, `serial_log_path`,
    `scenario_artifact_dir`, `scenario_step_timeout`.
    Run last on the direct-qemu lane because the final keypress
    shuts the guest down.
- Which lane runs where, the gate jobs, and the five required status
  checks are documented in `docs/testing.md` ("CI tiers"). Read that
  before changing a workflow; it is the authority, and this file
  deliberately does not restate it.
- Two behaviours that only matter when you are driving CI by hand: on
  a `workflow_dispatch` run of `functional-tests.yml`, an unselected
  target skips cleanly via a job-level `if:` (it does not report red);
  and instance readiness in the `shakenfist/actions` provisioning
  playbook gates on cloud-init completion, not just an open SSH port.

## Code Style

- Follow PEP 8 style guidelines
- Use single quotes for strings (except docstrings)
- Wrap lines at 80 characters
- Use `LOG.with_fields({...}).info()` for structured logging
- Add audit events for security-sensitive operations
- Diagrams in `docs/` are mermaid fenced blocks, not ASCII art, and
  prefer a vertical flow. See "Diagrams in the documentation" in
  `docs/development.md` for the conventions and the two deliberate
  plain-text exceptions.

## Review tracking

Kerbside carries whole-file human review state (`REVIEWS.md`,
`.vscode/*.weaudit*`, `.vscode/*.weaudit-shas.json`), maintained with
`tools/review-tracking.sh` (subcommands `stamp`, `prune`, `regen`,
`next`, `status`), which wraps `scripts/review-tracking.py` from a
local clone of the shakenfist/development repository. These are
deliberately *not* wired into git hooks — in a clone they run only
when invoked explicitly. On develop itself, the `prune-reviews`
workflow (`.github/workflows/prune-reviews.yml`, via
`tools/ci-prune-reviews.sh`) runs `prune` after every push and commits
the result back as shakenfist-bot, so stale marks are dropped as PRs
merge; the daily consistency audit in shakenfist/development files a
`Consistency: Human review coverage` issue when five or more in-scope
files need review. `REVIEWS.md` is generated; never edit it by hand.

Commits that add review marks must be signed -- the signature is the
attestation binding the reviewer to the reviewed content, and signing
is per-clone configuration that a fresh clone will not have. Confirm
`git config commit.gpgsign` is `true` (with `gpg.format` `x509` and
`gpg.x509.program` `gitsign`) before stamping, and check the result
with `git log --format='%h %G? %s'` -- `N` means the mark landed
unsigned. The bot's `prune` commits are exempt because pruning only
removes marks. See [docs/development.md](docs/development.md) for the
scope definition and the signing setup, and
https://github.com/shakenfist/development/blob/main/docs/code-review-tracking.md
for the session workflow.

## Configuration

Configuration is loaded from:
1. Environment variables (`KERBSIDE_*`)
2. INI file (path from `KERBSIDE_CONFIG_PATH` or `/etc/kerbside/kerbside.conf`)
3. Default values

Key configuration for development:
- `SQL_URL` - Database connection string
- `LOG_OUTPUT_PATH` - Set to `stdout` for console logging
- `LOG_VERBOSE` - Enable debug logging

## Debugging Tips

### Check Active Sessions

```sql
SELECT * FROM proxychannels;
SELECT * FROM consoletokens WHERE expires > NOW();
```

### Proxy Process Debugging

The daemon supervises the Rust proxy as a single child process (one tokio
task per connection, not a worker process per connection). To see the daemon
and its proxy child:
```bash
ps aux | grep kerbside
```
The proxy's `tracing` output is inherited by the daemon's stderr; per-channel
activity is visible in the Prometheus `/metrics` endpoint.

## Common Pitfalls

1. **Token Expiry**: Console tokens have configurable expiry. Ensure the
   maintenance loop is running to reap expired tokens.

2. **TLS Certificate Paths**: The proxy requires valid TLS certificates.
   Check `PROXY_HOST_CERT_PATH` and `PROXY_HOST_CERT_KEY_PATH` config.

3. **Database Connections**: SQLAlchemy sessions should be properly closed.
   Use context managers or explicit `session.close()`.

4. **Vendored sfui**: `kerbside/api/static/sfui/` is a verbatim copy of
   the shakenfist/sfui design system, stamped with its source commit in
   `.sfui-commit`. Never edit it in place: change canonical sfui and
   re-vendor, or the next sync silently discards the change and the
   consistency audit reports the drift. See "Vendored web assets" in
   `docs/development.md`. `login.html` and `consoles.html` are
   converted onto `base-sfui.html`; `sessions.html`, `sources.html`
   and `audit.html` still extend the old `base.html` until phase 6.
   Icons that need to follow the theme (an SVG loaded via `<img>`
   cannot -- `currentColor` resolves against the SVG's own isolated
   document, not the page) are inline `{% include %}`s of the SVGs
   under `kerbside/api/templates/icons/`, not static assets.

## Dependency Management

### Indirect Dependency Pinning

Dependencies are declared in `pyproject.toml`. Indirect (transitive)
dependencies are pinned in the same file, in a block delimited by
`# START_OF_INDIRECT_DEPS` and `# END_OF_INDIRECT_DEPS` marker comments.
Both markers are load-bearing: `tools/pin-indirect-dependencies.sh` hard-fails
unless each appears exactly once, and in that order.

A daily CI job (`pin-indirect-dependencies.yml`) runs that script, which
**regenerates the block wholesale** rather than appending to it. It demotes the
existing pins to pip constraints and re-resolves the direct dependencies
against them, so surviving pins keep exactly their current versions (Renovate
remains the only thing that moves a version) while pins nothing requires any
more are removed. Renovate bumps versions; this job adds and reaps entries.

**Never hand-edit anything between the two markers** — the next nightly run
deletes whatever it finds there. Add new direct dependencies to the main
dependencies list *above* `# START_OF_INDIRECT_DEPS`. Prefer an exact version:
a direct dependency is excluded from the generated block only if it is already
declared elsewhere in the file, which now includes unversioned declarations.

The script can be run locally for a dry run. Without `GITHUB_TOKEN` it prints
the diff instead of pushing a branch, but note that it rewrites `pyproject.toml`
in place either way — `git checkout -- pyproject.toml` to discard.

Only `[project] dependencies` are resolved. Optional-dependency extras (the
`test` extra, which carries openstacksdk, keystoneauth1 and the grpc tooling)
are not installed, so their transitive requirements are neither pinned nor
reaped.

**Packages that must never be pinned** are marked with a `# never-pin: <name>`
comment anywhere in `pyproject.toml`, one package per line. This is a generic
escape hatch, not a special case in the workflow.

The canonical example is **pydantic-core**. Each pydantic release exact-pins
(`==`) its matching pydantic-core, so a pin of our own is either redundant or
conflicting — Renovate bumping the two out of lockstep broke all CI installs
(PR #198). It carries a `# never-pin: pydantic-core` marker, and renovate.json
disables updates for it. Do not re-add a pydantic-core pin to `pyproject.toml`.

## External Dependencies

### Required Python Packages

- Flask, Flask-RESTful, Flask-JWT-Extended - Web framework
- SQLAlchemy - Database ORM
- Alembic - Database migrations
- cryptography - TLS and encryption
- prometheus_client - Metrics
- shakenfist_utilities - Logging utilities
- psutil - Process management

### Cloud-Specific Dependencies

- `shakenfist_client` - For Shaken Fist integration
- `ovirtsdk4` - For oVirt integration
- `keystoneauth1`, `novaclient` - For OpenStack integration

## Claude Code Skills

Claude skills for common tasks are in `.claude/skills/`:

- `add-database-migration.md` - Step-by-step guide for creating Alembic
  database migrations, including model updates and documentation.
- `add-source-type.md` - Guide for adding new cloud source implementations,
  covering the full workflow from source class to tests and docs.

Project-specific instructions are in `.claude/CLAUDE.md`.

## Related Repositories

- **kerbside-patches**: Upstream patches for OpenStack/Kolla integration
- **shakenfist**: Shaken Fist hypervisor platform
- **shakenfist/ryll**: Upstream Rust SPICE client (built into the loadtest image)
