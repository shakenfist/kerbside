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
| `kerbside/proxy.py` | Core proxy implementation - start here for connection handling |
| `kerbside/api.py` | REST API endpoints and web UI |
| `kerbside/db.py` | Database models (Source, Console, ConsoleToken, ProxyChannel, AuditEvent) |
| `kerbside/main.py` | Daemon entry point and maintenance loop |
| `kerbside/config.py` | Pydantic-based configuration |
| `kerbside/spiceprotocol/__init__.py` | SpiceClient class for hypervisor connections |
| `kerbside/spiceprotocol/packets/linkmessages.py` | SPICE handshake protocol |
| `kerbside/rpc/kerbside.proto` | KerbsideProxy gRPC contract fronting the DB for the proxy |
| `kerbside/rpc/servicer.py` | gRPC servicer implementing the contract against db.py |
| `kerbside/rpc/server.py` | serve()/stop() hosting the servicer over a unix socket in the daemon |
| `rust/kerbside-proxy/` | Rust reimplementation of the SPICE proxy (in progress): TLS termination, handshake, gRPC-authorised inspection-first relay that enforces an L0+L1 SPICE firewall (phase 4). Builds in Docker via its Makefile |
| `rust/kerbside-proxy/src/policy.rs` | The `Policy`/`Verdict` seam and the phase-4 firewall engine: `FirewallPolicy` (tunable knobs), `EnforcementMode` (Enforce/WarnOnly), `EnforcingPolicy` (L0 size/rate caps + L1 allowlist lookup), `VerdictTally` (coalesced per-connection audit) |
| `rust/kerbside-proxy/src/allowlist.rs` | The compiled-in L1 message-type grammar: `classify(channel, dir, msg_type) -> Allowed \| Disallowed \| ChannelUnmodeled`, derived from the ryll `shakenfist-spice-protocol` name tables |
| `kerbside/proxy_supervisor.py` | Phase 5: launches/supervises the Rust `kerbside-proxy` binary as a daemon child when `PROXY_IMPLEMENTATION=rust` — `find_proxy_bin()` (env/PATH/dev-build resolution), `build_proxy_argv()` (config → CLI flags), `terminate_child()` (SIGTERM-then-SIGKILL with a deadline) |
| `kerbside/db.py` (`SessionTermination`, migration `c4e7a1b9d2f3`) | Phase 5: the `session_terminations` intent table (`request_session_termination`, `get_terminations_for_node`, `reap_session_terminations`) that bridges API-driven termination to each proxy node's local `ProxyControl` push — see "Session termination" below |
| `rust/kerbside-proxy/src/session.rs` (`SessionRegistry`) | Phase 5: the `session_id -> CancellationToken` registry the relay's `select!` and `ProxyControl`'s `TerminateSession` handler share, plus the shutdown-time `terminate_all()` drain |
| `kerbside/sources/static.py` | Static source driver: reads VM-to-console mapping from an inline list in sources.yaml; designed for CI pipelines and ad-hoc debugging (no control plane required) |

## Architecture Patterns

### Multiprocess Worker Model

The proxy uses a multiprocess architecture:
- Main proxy process accepts connections via `SpiceListener`
- Each client connection spawns a worker process (`SpiceTLSSession`)
- Workers are monitored and reaped by the parent process
- State is shared via the database, not shared memory

### State Machine Pattern

`SpiceTLSSession` uses a state machine for connection handling:
1. `ClientSpiceLinkMess` - Initial handshake
2. `ClientPassword` - Authentication
3. `ClientProxy` / `ServerProxy` - Traffic relay

The `client_next_packet` and `server_next_packet` attributes control state
transitions.

### Exception Handling in Proxy

Connection errors must be caught and converted to `ConnectionRefused` to ensure
proper cleanup. Key exceptions to handle:

```python
from .spiceprotocol.packets.linkmessages import (
    BadMagic, BadMajor, BadMinor,
    HandshakeFailed,
    ConnectionError as SpiceConnectionError
)
```

The exception handler at line ~290 in `proxy.py` handles graceful termination.

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
system protobuf needed). The crate depends on the ryll
`shakenfist-spice-protocol` crate as a git dependency pinned to a specific
rev in `Cargo.toml`; bump the `rev` (and commit the updated `Cargo.lock`)
when picking up ryll changes. CI runs fmt/clippy/test/build via
`.github/workflows/rust.yml`; end-to-end verification against qemu is
`tools/direct-qemu/VERIFY-RUST-PROXY.md`.

#### Packaging and release (phase 6)

The crate is published to PyPI as a separate `kerbside-proxy` package —
a maturin `bindings = "bin"` wheel (`rust/kerbside-proxy/pyproject.toml`)
that carries the compiled binary in the wheel's `*.data/scripts/` dir, so
`pip install` puts `kerbside-proxy` on `PATH` and phase 5's
`find_proxy_bin()` resolves it via `shutil.which`. `kerbside` exact-pins
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

#### SPICE firewall (phase 4)

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
session, run the harness in `tools/direct-qemu/VERIFY-FIREWALL.md`: it
brings the mock gRPC server up delivering a `WARN_ONLY` `FirewallPolicy`,
drives a real SPICE client (remote-viewer/virt-viewer/ryll headless)
through the proxy, then asserts
`kerbside_proxy_firewall_verdicts_total` is entirely zero (a clean
capture) via `verify-rust-proxy.sh assert-firewall`. Any non-zero
`observed` verdict on legitimate traffic means the compiled allowlist or
a size cap needs widening — never the verdict weakening. The same harness
also has a deny-token/deny-all mode for exercising the
`PermissionDenied` denial path end to end.

#### Daemon supervision + session termination (phase 5)

`PROXY_IMPLEMENTATION` (`kerbside/config.py`, default `python`) selects
whether `kerbside daemon run` forks the in-process Python proxy (unchanged
default) or supervises the Rust `kerbside-proxy` binary as a child via
`kerbside/proxy_supervisor.py`. When `rust`, the daemon binds the gRPC UDS
server before launching the child (the proxy dials it at startup), polls
child liveness, and forwards SIGTERM with a 15-second deadline before
SIGKILLing — exiting non-zero if the child dies. The proxy binds its
`/metrics` server on its own `--metrics-address` (default loopback, config
`PROMETHEUS_METRICS_ADDRESS`) rather than the public VDI address.

API-driven session termination now drops in-flight connections, not just
new ones. Because the REST API and proxy nodes may be on different
machines (and a load-balanced session's channels may span nodes), the only
shared bus is the database: `ConsolesTerminate`/`SessionTerminate`
(`api.py`) insert a `session_terminations` intent row; each node's daemon
polls it (scoped to sessions live on that node) in its `ProxyControl`
handler (`servicer.py`) and pushes `TerminateSession`; the Rust proxy's
`SessionRegistry` (`session.rs`) cancels that session's shared
`CancellationToken`, and the relay's `select!` (`relay.rs`) tears every
channel down. A TTL reaper cleans up old intent rows. The API always
records the intent regardless of `PROXY_IMPLEMENTATION`, but only the Rust
proxy consumes `ProxyControl` today — a `python`-mode node's in-flight
connections are unaffected, unchanged from before phase 5. See
`docs/proxy-architecture.md` ("Rust Proxy: Process Supervision and Session
Termination") for the full flow and `ARCHITECTURE.md` for the
distributed-deployment rationale.

To validate live termination against a real client without a full
API+daemon+MariaDB stack, use `tools/direct-qemu/VERIFY-TERMINATION.md`:
the mock gRPC server's `ProxyControl` stream emits a one-shot
`TerminateSession` a configurable number of seconds after the first
authorization (`MOCK_GRPC_TERMINATE_AFTER`), standing in for the API/DB
leg so the harness exercises the proxy-side cancellation path live.

### Direct-qemu proxy matrix (phase 7)

`.github/workflows/direct-qemu-functional.yml` runs the lane as a
`strategy.matrix.proxy: [python, rust]`. Both legs run the identical
smoke + banner + Sextant scenario (`run-scenario.sh`) against the real
daemon+API+MariaDB stack with a headless ryll client; the Rust proxy
passing the same oracle the Python proxy passes is the functional-parity
proof. `PROXY_IMPLEMENTATION` flows from the matrix value through
`lane-up.sh` into `start-kerbside.sh`, which selects the proxy the daemon
supervises (and, for `rust`, pre-checks the binary via `find_proxy_bin()`).

The Rust leg additionally:

- Builds and installs the `kerbside-proxy` wheel into the kerbside venv
  (`install-proxy-wheel.sh` → `build-proxy-wheel.sh --native`), so
  `find_proxy_bin()` resolves it via `shutil.which` on `PATH` — the real
  phase-6 install path, given CI coverage here.
- Runs `verify-terminate-live.sh` (Rust-only): on an isolated lane, calls
  the REST terminate endpoint and asserts the in-flight connection drops
  via the proxy log `session terminated by control plane`, exercising the
  phase-5 DB→`ProxyControl` bridge end to end (not the mock).

Both legs run `run-loadtest.sh` (non-gating, `continue-on-error`): it
drives `loadtests/latency/orchestrator.py` to sample relay PING/PONG RTT
through the leg's proxy and records p50/p95 as an artifact; the
Python-vs-Rust comparison is read off the two legs. This is distinct from
the local mock harness (`VERIFY-RUST-PROXY.md`), which needs no daemon or
database.

### Modifying SPICE Protocol Handling

Protocol packets are in `kerbside/spiceprotocol/packets/`:
- Each packet type has a parser class
- Parsers return consumed byte count (0 if incomplete)
- Use `struct.unpack_from()` for binary parsing

See the protocol documentation in `docs/` for detailed information:
- `docs/protocol-overview.md` - SPICE protocol fundamentals
- `docs/spice-link-protocol.md` - Connection handshake and authentication
- `docs/channel-protocols.md` - Per-channel message formats
- `docs/usb-redirection.md` - USB device redirection protocol
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
- The "Test cloud compatibility" lane (`functional-tests.yml`,
  `ovirt_matrix` + `openstack_matrix`) runs per-PR, both legs blocking.
  On a `workflow_dispatch` run, an unselected target skips cleanly via a
  job-level `if:` (it does not report red). Instance readiness in the
  `shakenfist/actions` provisioning playbook gates on cloud-init
  completion, not just an open SSH port.

## Code Style

- Follow PEP 8 style guidelines
- Use single quotes for strings (except docstrings)
- Wrap lines at 80 characters
- Use `LOG.with_fields({...}).info()` for structured logging
- Add audit events for security-sensitive operations

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

### Enable Traffic Inspection

Set in config:
```ini
TRAFFIC_INSPECTION=true
TRAFFIC_INSPECTION_INTIMATE=true  # Warning: logs keystrokes!
TRAFFIC_OUTPUT_PATH=/tmp/kerbside-traffic
```

### Check Active Sessions

```sql
SELECT * FROM proxychannels;
SELECT * FROM consoletokens WHERE expires > NOW();
```

### Proxy Process Debugging

The proxy renames worker processes with `setproctitle` for visibility:
```bash
ps aux | grep kerbside
```

## Common Pitfalls

1. **Exception Handling**: Uncaught exceptions in `SpiceTLSSession` methods
   cause silent connection drops. Always catch and convert to appropriate
   exception types.

2. **Socket Blocking**: Server sockets are set non-blocking after connection.
   Use `select()` for I/O multiplexing.

3. **Token Expiry**: Console tokens have configurable expiry. Ensure the
   maintenance loop is running to reap expired tokens.

4. **TLS Certificate Paths**: The proxy requires valid TLS certificates.
   Check `PROXY_HOST_CERT_PATH` and `PROXY_HOST_CERT_KEY_PATH` config.

5. **Database Connections**: SQLAlchemy sessions should be properly closed.
   Use context managers or explicit `session.close()`.

## Dependency Management

### Indirect Dependency Pinning

Dependencies are declared in `pyproject.toml`. Indirect (transitive) dependencies
are pinned in the same file, in a section ending with a `# END_OF_INDIRECT_DEPS`
marker comment. A daily CI job (`pin-indirect-dependencies.yml`) detects new
unpinned indirect dependencies and creates PRs to pin them. The marker comment
must not be removed, as the CI job uses `sed` to insert new entries before it.

When adding a new direct dependency to `pyproject.toml`, place it in the main
dependencies list above the "Indirect dependencies" comment. Do not place it
after the `# END_OF_INDIRECT_DEPS` marker.

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

## Related Repositories

- **kerbside-patches**: Upstream patches for OpenStack/Kolla integration
- **shakenfist**: Shaken Fist hypervisor platform
- **shakenfist/ryll**: Upstream Rust SPICE client (built into the loadtest image)
