# AI Agent Guidelines for Kerbside

Conventions and gotchas for working on Kerbside that you cannot infer
by reading the code. Everything else is documented elsewhere; this file
points you there rather than restating it.

## What Kerbside is

Kerbside is a SPICE VDI protocol proxy that enables remote console access to
VMs across multiple cloud platforms (Shaken Fist, OpenStack, oVirt). It handles
SPICE protocol negotiation, authentication, and bidirectional traffic relay.

## Where the documentation lives

| Question | Document |
|----------|----------|
| How do the components fit together? | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| How does the proxy work internally? | [`docs/proxy-architecture.md`](docs/proxy-architecture.md) |
| How do I build, debug and package it? | [`docs/development.md`](docs/development.md) |
| How do I run the tests, and what gates a PR? | [`docs/testing.md`](docs/testing.md) |
| What are the configuration settings? | [`docs/configuration.md`](docs/configuration.md) |
| How do I install and deploy it? | [`docs/installation.md`](docs/installation.md) |
| How do I see it running, quickly? | [`demo/README.md`](demo/README.md), the compose demo |
| How is it deployed against a specific cloud? | [`docs/use-cases/`](docs/use-cases/) |
| How do I exercise the proxy against real qemu? | [`docs/direct-qemu-harness.md`](docs/direct-qemu-harness.md) |
| What are the database tables? | [`docs/schema.md`](docs/schema.md) |
| How do console sources work? | [`docs/console-sources.md`](docs/console-sources.md) |
| How does the SPICE protocol work? | [`docs/spice/protocol-overview.md`](docs/spice/protocol-overview.md) |
| How do I audit a change before pushing? | [`PUSH-AUDIT.md`](PUSH-AUDIT.md) |

[`docs/index.md`](docs/index.md) is the full index.

A master plan's final phase runs that audit over the plan's
accumulated diff, not over the last phase alone;
[`PLAN-TEMPLATE.md`](PLAN-TEMPLATE.md) carries the convention.

## Key files to understand

| File | Purpose |
|------|---------|
| `kerbside/api.py` | REST API endpoints and web UI |
| `kerbside/db.py` | Database models (Source, Console, ConsoleToken, ProxyChannel, AuditEvent, SessionTermination) |
| `kerbside/main.py` | Daemon entry point and maintenance loop |
| `kerbside/config.py` | Pydantic-based configuration |
| `kerbside/rpc/kerbside.proto` | KerbsideProxy gRPC contract fronting the DB for the proxy |
| `kerbside/rpc/servicer.py` | gRPC servicer implementing the contract against db.py |
| `kerbside/rpc/server.py` | serve()/stop() hosting the servicer over a unix socket in the daemon |
| `kerbside/proxy_supervisor.py` | Launches and supervises the Rust proxy as the daemon's child |
| `kerbside/sources/static.py` | Static source driver for CI pipelines and ad-hoc debugging (no control plane required) |
| `rust/kerbside-proxy/` | The SPICE proxy — start here for connection handling. Builds in Docker via its Makefile |
| `rust/kerbside-proxy/src/policy.rs` | The `Policy`/`Verdict` seam and the firewall engine |
| `rust/kerbside-proxy/src/allowlist.rs` | The compiled-in L1 message-type grammar, derived from ryll's `shakenfist-spice-protocol` name tables |
| `rust/kerbside-proxy/src/session.rs` | `SessionRegistry`: the `session_id -> CancellationToken` map the relay and `ProxyControl` share |

## Common tasks

### Adding a new source type

1. Create a new file in `kerbside/sources/`
2. Inherit from `BaseSource` (see `sources/base.py`)
3. Implement `__call__()` to yield console entries
4. Register the type in `kerbside/main.py:_parse_sources()` — it
   dispatches on `source['type']` through a hardcoded chain, so a
   source class that is not added there is never instantiated

The `add-source-type` Claude skill walks the full workflow.

### Adding a new API endpoint

1. Create a Flask-RESTful Resource class in `api.py`
2. Add the route in the `api.add_resource()` section
3. Use `@jwt_required()` decorator for authenticated endpoints
4. Return both HTML and JSON responses where appropriate

### Adding database migrations

```bash
alembic revision -m "description_of_changes"
# Edit the generated file in kerbside/migrations/versions/
alembic upgrade head
```

The `add-database-migration` Claude skill covers the model and
documentation updates that go with it.

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

### Modifying SPICE protocol handling

SPICE wire-format parsing lives in the Rust proxy, which reuses the ryll
`shakenfist-spice-protocol` crate (pinned by git rev in `Cargo.toml`);
the L1 firewall grammar is in `rust/kerbside-proxy/src/allowlist.rs`.
The protocol reference is under [`docs/spice/`](docs/spice/), and the
external source of truth is
https://www.spice-space.org/spice-protocol.html.

## Things that will bite you

- **Bump `tonic`, `tonic-prost`, `tonic-prost-build` and `prost`
  together.** A runtime crate that moves without its code generator
  emits stubs that will not compile. The `tonic-prost-rust` Renovate
  group exists to keep them in one PR.

- **Never widen a firewall verdict to make traffic pass.** A non-zero
  `observed` verdict on legitimate traffic means the compiled allowlist
  or a size cap needs widening — not the verdict weakening. Validate
  with the warn-only capture in
  [`docs/direct-qemu-harness.md`](docs/direct-qemu-harness.md).

- **The demo cannot be built against a checkout from a git
  worktree.** `KERBSIDE_SOURCE=/src docker compose build kerbside`
  needs the repository's git metadata in the build context, which a
  worktree does not provide; run it from an ordinary clone. The
  default build installs the released package from PyPI and works
  anywhere. Issue #326 tracks the underlying packaging fragility.

- **Renaming a `Can enqueue: <lane>` gate job blocks every merge**
  until the develop ruleset is updated to match. Both the direct-qemu
  and `sf-e2e` gate jobs are required status checks.

- **Never hand-edit between `# START_OF_INDIRECT_DEPS` and
  `# END_OF_INDIRECT_DEPS` in `pyproject.toml`.** The nightly
  `pin-indirect-dependencies.yml` job regenerates that block wholesale
  and deletes whatever it finds there. Add new direct dependencies
  *above* the start marker, preferring an exact version. Packages that
  must never be pinned carry a `# never-pin: <name>` comment — the
  canonical case is pydantic-core, which each pydantic release
  exact-pins itself, and which broke every CI install when Renovate
  moved the two out of lockstep (PR #198). See "Dependency pinning" in
  [`docs/development.md`](docs/development.md).

- **Never edit `kerbside/api/static/sfui/` in place.** It is a verbatim
  copy of shakenfist/sfui stamped with its source commit in
  `.sfui-commit`; change canonical sfui and re-vendor, or the next sync
  silently discards the change and the consistency audit reports the
  drift. Icons that need to follow the theme must be inline
  `{% include %}`s of the SVGs under
  `kerbside/api/templates/icons/` — an SVG loaded via `<img>` cannot
  follow it, because `currentColor` resolves against the SVG's own
  isolated document. See "Vendored web assets" in
  [`docs/development.md`](docs/development.md).

- **Never attach an event listener to content on a polled page.**
  Every `refresh=True` page morphs a freshly fetched `#kb-content`
  onto the live one every 30 seconds rather than reloading, so live
  nodes survive a tick and a per-node listener added after one
  accumulates a duplicate on every tick. Delegate from `#kb-content`
  or above it. See "Page polling" in
  [`docs/development.md`](docs/development.md).

- **Scope oVirt object lookups to the cluster.** The CI lane runs two
  datacenters with identically-named networks and vNIC profiles, so a
  bare name match silently picks the wrong one and fails with a 409
  only sometimes (issue #283).

- **New log-derived test oracles must strip ANSI and keep "would not
  parse" separate from "was empty".** Conflating them (issue #272)
  reported a broken parser as a security failure for two days.

- **A link out of `docs/` must be an absolute URL.** `docs/` is
  synchronised into shakenfist/shakenfist and published on
  shakenfist.com, where the tree above `docs/` does not exist, so
  `../ARCHITECTURE.md` renders correctly on GitHub and 404s on the
  site. Links that stay inside `docs/` should stay relative; they move
  with the tree and work in both renderings.

- **The credential scan runs on every change, including
  documentation-only ones.** It is the one CI job not gated on
  `check_paths`, it scans all of history rather than the diff, and it
  fails on a credential-shaped string in a code sample as readily as
  on a real key. Do not silence one by widening `.gitleaks.toml`;
  suppression has two mechanisms and picking the wrong one blinds the
  scanner to future leaks. See "The credential scan" in
  [`docs/testing.md`](docs/testing.md).

- **`REVIEWS.md` is generated; never edit it by hand.** Commits that
  add review marks must be signed — confirm `git config
  commit.gpgsign` is `true` (with `gpg.format` `x509` and
  `gpg.x509.program` `gitsign`) before stamping, and check with
  `git log --format='%h %G? %s'`; `N` means the mark landed unsigned.
  See "Review tracking" in [`docs/development.md`](docs/development.md).

## Code style

- Follow PEP 8 style guidelines
- Use single quotes for strings (except docstrings)
- Wrap lines at 80 characters
- Use `LOG.with_fields({...}).info()` for structured logging
- Add audit events for security-sensitive operations
- Diagrams in `docs/` are mermaid fenced blocks, not ASCII art, and
  prefer a vertical flow. See "Diagrams in the documentation" in
  [`docs/development.md`](docs/development.md) for the conventions and
  the two deliberate plain-text exceptions.

## Claude Code skills

Claude skills for common tasks are in `.claude/skills/`:

- `add-database-migration/` — creating Alembic migrations, including
  model updates and documentation.
- `add-source-type/` — adding new cloud source implementations, from
  source class through tests and docs.

Project-specific instructions are in `.claude/CLAUDE.md`.

## Related repositories

- **kerbside-patches** — upstream patches for OpenStack/Kolla integration
- **shakenfist** — the Shaken Fist hypervisor platform
- **shakenfist/ryll** — the Rust SPICE client (built into the loadtest image)
