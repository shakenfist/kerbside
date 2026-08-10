# Kerbside Architecture

Kerbside is a SPICE VDI protocol proxy that provides remote console access to
VMs running in virtualization clusters (Shaken Fist, OpenStack, oVirt). It is
split into a pure-Python control plane (the REST API and the daemon) and a
Rust SPICE proxy the daemon supervises: the proxy terminates client SPICE
connections, and the control plane identifies which VM to proxy to based on
authentication tokens; traffic is relayed bidirectionally between client and
server.

## High-Level Architecture

```
                                    +------------------+
                                    |   Web Browser    |
                                    |   (Admin UI)     |
                                    +--------+---------+
                                             |
                                             | HTTPS
                                             v
                                    +--------+---------+       +--------------+
                                    | kerbside (Python)|       |   MariaDB    |
                                    |  REST API +      +<----->+  (shared bus)|
                                    |  daemon          |       +------+-------+
                                    +--------+---------+              ^
                                             | supervises            |
                                             | + gRPC/UDS            | DB
                                             v                       |
+------------------+     TLS       +---------+----------+            |
|  SPICE Client    +-------------->+  kerbside-proxy    +------------+
|  (virt-viewer)   |    :5900      |  (Rust, tokio)     |
+------------------+               +---------+----------+
                                             |
                    +------------------------+------------------------+
                    |                        |                        |
                    v                        v                        v
           +--------+------+        +--------+------+        +--------+------+
           | Shaken Fist   |        |   OpenStack   |        |     oVirt     |
           | Hypervisors   |        |   Hypervisors |        |   Hypervisors |
           +---------------+        +---------------+        +---------------+
```

## Core Components

### 1. Main Process (`main.py`)

The main entry point orchestrates the system lifecycle:

- Parses source configuration from `sources.yaml`
- Supervises the Rust `kerbside-proxy` binary as a child process
  (`kerbside/proxy_supervisor.py`; see "Proxy Layer" below)
- Hosts the control-plane gRPC service (see below) on a background
  thread over a unix domain socket
- Runs a maintenance loop every 60 seconds to:
  - Refresh console listings from configured sources
  - Reap expired authentication tokens
  - Reap expired `session_terminations` intent rows (phase 5, see below)
  - Handle source configuration changes

### 2. Control-plane gRPC service (`rpc/`)

The `KerbsideProxy` gRPC service (`kerbside/rpc/kerbside.proto`,
servicer in `kerbside/rpc/servicer.py`, hosting in
`kerbside/rpc/server.py`) fronts the database operations the SPICE
proxy needs, so a separate proxy process can consult Python for
authorization and channel bookkeeping instead of accessing MariaDB
directly. Python owns the database and policy; the proxy consults this
service.

It is exposed over a filesystem-guarded unix domain socket
(`API_SOCKET_PATH`, default `/run/kerbside/api.sock`) with insecure
gRPC credentials (the peer is a trusted local process), hosted on a
`ThreadPoolExecutor` in the daemon process. Errors are signalled via
gRPC status codes.

| RPC | Maps to | Purpose |
|-----|---------|---------|
| `AuthorizeConnection` | `get_token_by_token` + `get_source` + `get_console` | Resolve a decrypted token to a hypervisor `Target`, or `Denied`; records the session and the `Channel created` audit |
| `RegisterChannel` | `record_channel_info_by_ref` | Pre-authorization channel record |
| `RecordAuditEvent` | `add_audit_event` | Write an audit event |
| `DeregisterChannel` | `remove_channel_by_ref` | Remove a channel at teardown |
| `ClearNodeChannels` | `remove_node_channels` | Clear stale channel rows at proxy startup |
| `ProxyControl` (streaming) | `get_terminations_for_node` | Daemon→proxy control channel: interleaves `Heartbeat`s with real `TerminateSession` events (phase 5) for sessions marked for termination that are live on this node; policy push is future work |

`ProxyControl` is deliberately **local only** — one stream between a daemon
and the single proxy it supervises on the same host, over the same UDS as
every other RPC. It is not a mechanism for reaching a proxy on another
machine (see "Session termination" below).

The `.proto` is compiled with `tox -egenprotos` (see
`tools/gen-protos.sh`); generated stubs are checked in under
`kerbside/rpc/`. Channel rows are keyed by a proxy-supplied
`connection_ref` on the `proxychannels` table (which has a surrogate `id`
primary key).

### 3. Proxy Layer (`rust/kerbside-proxy/`)

The SPICE proxy is a Rust binary. It terminates client TLS, performs the
SPICE link handshake, and relays traffic as async tokio tasks (one per
connection). Rather than accessing the database directly, it consults the
control-plane gRPC service (component 2) over the unix socket for
authorization and channel/audit bookkeeping, and it reuses the ryll
`shakenfist-spice-protocol` crate for the SPICE wire format. It binds the
secure (5900) and insecure (5901) VDI ports — the insecure port issues a
`need_secured` redirect to TLS — and exposes its own Prometheus `/metrics`
endpoint on `--metrics-address` (default loopback, config
`PROMETHEUS_METRICS_ADDRESS`) rather than the public VDI address, since the
endpoint is unauthenticated. It is also an L0+L1 SPICE firewall (see
"Firewall" below).

**Connection flow:** accept → TLS terminate → SPICE link handshake →
`AuthorizeConnection` over the UDS (decrypt the token, resolve the
hypervisor `Target`, or `Denied`) → connect the backend leg to the
hypervisor → bidirectional framed relay, with every message checked against
the firewall policy delivered in the authorize reply.

**Supervision.** `daemon_run` (`main.py`) binds the gRPC UDS server
*first* — the proxy dials it at startup (`ClearNodeChannels`) and lazily
thereafter, so the socket must already exist — then launches
`kerbside-proxy` as a `subprocess.Popen` child via
`kerbside/proxy_supervisor.py`: `find_proxy_bin()` resolves the binary
(`KERBSIDE_PROXY_BIN` env override → an installed `kerbside-proxy` on
`PATH`, from the wheel → the in-repo dev build dir) and `build_proxy_argv()`
maps config to the proxy's CLI flags (the firewall knobs are NOT among them
— they are delivered per connection over gRPC, see below). The daemon polls
child liveness each second; on SIGTERM it forwards SIGTERM to the child with
a 15-second deadline (longer than the proxy's own 10-second drain, so the
proxy can finish draining first) before SIGKILLing it, and exits non-zero
if the child dies unexpectedly.

**Session termination drops in-flight connections.** Terminating a
session via the API drops the client's live SPICE channels, not just its
ability to make *new* connections. Kerbside can run distributed — the REST
API and proxy nodes may be on different machines, and a load balancer can
spread one session's channels across several proxy nodes — so the API
cannot signal a specific proxy directly; the shared MariaDB is the only bus
every component can reach. Termination is therefore threaded through the
database as an explicit intent:

1. `ConsolesTerminate`/`SessionTerminate` (`api.py`) keep the existing
   token expire/remove and additionally insert a `session_terminations`
   row (`session_id`, `requested_at`, `reason`) via `db.py`'s
   `request_session_termination`.
2. Each proxy node's daemon, in its local `ProxyControl` stream handler
   (`servicer.py`), polls `get_terminations_for_node(NODE_NAME)` — the
   sessions that are BOTH marked for termination AND have a live
   `proxychannels` row on this node — and pushes a `TerminateSession`
   event for each one not already sent on this stream, interleaved with
   heartbeats. A session only live on another node is that node's job; a
   merely-expired (not explicitly terminated) token is never pushed.
3. The Rust proxy's `SessionRegistry` (`session.rs`) maps `session_id ->
   CancellationToken`, refcounted across that session's channels. On
   `TerminateSession` (`rpc.rs::run_proxy_control`), the registry cancels
   the token; the relay's `select!` (`relay.rs`) has a third arm on
   `token.cancelled()` alongside the two pumps, so every channel of the
   session tears down cleanly and the client is disconnected. Cancelling
   an unregistered/already-gone session is a harmless no-op, so a late or
   duplicate event (a node that pushed the same id twice, or one that
   arrives after the session already ended) is safe.
4. A TTL reaper in the maintenance loop (`reap_session_terminations`,
   5-minute default) deletes aged intent rows once every node has had time
   to poll and act.

**Graceful drain on shutdown.** On SIGTERM,
`shutdown_signal` stops the proxy's listeners from accepting new
connections, cancels every live session via the same `SessionRegistry`
(`terminate_all`), then waits up to a 10-second deadline for the active
connection count to reach zero before the process exits — sized below the
daemon's 15-second SIGTERM-to-SIGKILL window so a supervised restart drains
in-flight sessions rather than abruptly cutting them.

The relay is inspection-first: every framed SPICE message is passed through
a `Policy` (the `Policy`/`Verdict` seam) before being forwarded, and as of
phase 4 that seam is a real, **enforcing** application-level SPICE
firewall, on by default. `EnforcingPolicy` (`policy.rs`) consults:

- **L1 (message grammar)**: a compiled-in per-channel, per-direction
  message-type allowlist (`allowlist.rs`), derived from the ryll
  `shakenfist-spice-protocol` name tables unioned with the SPICE
  common-base opcodes. A disallowed type on a modeled channel (main,
  display, inputs, cursor, playback, and usbredir/port/webdav via the
  spicevmc tables) terminates the session; record/smartcard/tunnel have no
  modeled grammar and get observe-only handling instead of a type-based
  terminate.
- **L0 (resource limits)**: per-(channel, direction) message-size caps
  (tight on the inputs/cursor client directions, generous elsewhere, both
  below the relay's unconditional 16 MiB absolute frame guard), a
  rate/throughput ceiling (disabled by default), a 15-minute idle-read
  timeout, and client-side TCP keepalive — closing the phase-3 deferred
  permit-pinning findings.

Policy is delivered per-connection over gRPC in the `AuthorizeConnection`
reply (`FirewallPolicy`, in `kerbside.proto`): Python continues to own and
tune policy (enforcement mode, permitted channels); the Rust proxy only
enforces it. A channel type the deployment forbids is denied before relay.
An `EnforcementMode::WarnOnly` mode downgrades every blocking verdict to
forward-and-log (`action=observed` in both the metric and the audit
summary) instead of terminating, so an operator can validate a
deployment's real traffic against the firewall before switching it to the
default `Enforce` mode. Verdicts are exported as the Prometheus metric
`kerbside_proxy_firewall_verdicts_total{channel,direction,rule,action}` and
coalesced into a single audit event per connection (never one per
message). L2 body validation, session recording, and L3 rewriting remain
future work; see `docs/plans/PLAN-rust-proxy-phase-04-firewall.md`.

### 4. API Layer (`api.py`)

Flask-based REST API with JWT authentication (Keystone integration for
OpenStack environments).

**Key Endpoints:**

| Endpoint | Purpose |
|----------|---------|
| `POST /auth` | Authentication (Keystone) |
| `GET /source` | List configured sources |
| `GET /console` | List all discovered consoles |
| `GET /console/<source>/<uuid>/console.vv` | Generate virt-viewer config |
| `GET /sf-console.vv?token=<jwt>` | Exchange a Shaken Fist Ed25519 JWT (verified offline) for a console token and virt-viewer config |
| `GET /session` | List active proxy sessions |
| `GET /session/<id>/terminate` | Kill specific session |

### 5. SPICE Protocol Handling

SPICE wire-format parsing lives in the Rust proxy, which reuses the ryll
`shakenfist-spice-protocol` crate (a rev-pinned git dependency in
`rust/kerbside-proxy/Cargo.toml`) for the link handshake, ticket
decryption, mini-header framing, and per-channel message types. The
firewall's L1 message-type grammar is derived from that crate in
`rust/kerbside-proxy/src/allowlist.rs`. See `docs/channel-protocols.md`
and `docs/spice-link-protocol.md` for the protocol reference.

**Channels the proxy models:**

- `main` - Connection control
- `display` - Display updates
- `inputs` - Mouse/keyboard input
- `cursor` - Cursor updates
- `port` - Port redirection
- `playback` / `record` - Audio channels
- `usbredir` - USB redirection

### 6. Database Layer (`db.py`)

SQLAlchemy ORM with Alembic migrations. Uses MySQL/MariaDB.

**Tables:**

| Table | Purpose |
|-------|---------|
| `sources` | Cloud source configurations |
| `consoles` | Discovered VM consoles |
| `consoletokens` | Authentication tokens with expiry |
| `proxychannels` | Active proxy connections |
| `auditevents` | Activity logging |
| `sf_token_jtis` | Spent Shaken Fist token `jti`s, enforcing single-use exchange |
| `sf_token_keys` | Cached per-source Shaken Fist signing public keys for offline JWT verification |

### 7. Source Abstraction (`sources/`)

Pluggable console discovery from different cloud platforms.

**Implementations:**

| Source | File | Description |
|--------|------|-------------|
| Shaken Fist | `shakenfist.py` | Uses `shakenfist_client` library; a `system` credential scrapes the whole cluster, caches the cluster's VDI token signing keys, and pins each console's `host_subject` from the node's SPICE cert subject |
| oVirt | `ovirt.py` | Uses `ovirtsdk4` library; scrapes the engine for console addresses and pins each VM's host certificate subject, and acquires a short-lived graphics-console ticket per `.vv` request. Kerbside dials the hypervisor directly and never reads an engine-generated `.vv`, so oVirt's own SPICE proxy is not in the path — see [docs/use-cases/ovirt.md](docs/use-cases/ovirt.md) |
| OpenStack | `api.py` | On-demand via Nova token validation |
| Static | `static.py` | Reads VM mapping from an inline `consoles:` list in sources.yaml; no external API calls; designed for CI and ad-hoc debugging |

The static driver stores tickets in the Console DB at
enumeration time via `db.add_console(..., ticket=...)`.  The
API layer reads those persisted tickets back at `.vv`-
generation time rather than making a per-request driver call.
This keeps the API-side change to a single `elif` branch that
skips the `db.store_console_ticket()` overwrite that would
otherwise erase the persisted value.  An example sources.yaml
for the static driver lives at
`etc/example-static-sources.yaml`.

## Data Flow

### Console Discovery

```
sources.yaml
    |
    v
_parse_sources() reads YAML config
    |
    v
Source class instantiated (ShakenFistSource/oVirtSource)
    |
    v
Source.__call__() yields console entries
    |
    v
db.add_console() stores in database
    |
    v
API returns console list to authenticated clients
```

### Client Connection

```
Client requests virt-viewer config via API
    |
    v
consoletoken.create_token() generates 48-char token
    |
    v
Token embedded in virt-viewer file as password
    |
    v
Client connects to proxy with encrypted password
    |
    v
Proxy decrypts and validates the token (AuthorizeConnection over gRPC)
    |
    v
db.get_console() retrieves hypervisor details
    |
    v
SpiceClient.connect() establishes server connection
    |
    v
Bidirectional proxy relay begins
```

## Configuration

Configuration uses Pydantic settings with INI file and environment variable
support. Environment variables (prefixed `KERBSIDE_`) take priority.

**Key Configuration Categories:**

- **Authentication**: Keystone integration, JWT secrets, token duration
- **Network**: Public FQDN, bind addresses, ports
- **Security**: TLS certificates, CA certificates
- **Database**: SQLAlchemy connection string
- **Monitoring**: Prometheus metrics port
- **Traffic Inspection**: Optional packet logging

See `etc/kerbside.conf.example` for a complete configuration reference.

## Security Model

1. **Client Authentication**: JWT tokens issued after Keystone validation
2. **Console Access**: Time-limited tokens (configurable expiry)
3. **TLS Everywhere**: Client-to-proxy and proxy-to-hypervisor connections
4. **Certificate Validation**: the backend hypervisor certificate chain is
   validated against the source CA. When the console carries a
   `host_subject`, it is also enforced: the certificate's subject must match
   under spice-common semantics (same attribute count, types, and order;
   values compared case-insensitively with whitespace folded), substituting
   for hostname verification. See `docs/plans/PLAN-host-subject.md`.
5. **Offline Shaken Fist token verification**: Shaken Fist consoles are
   accessed by exchanging a short-lived Ed25519-signed JWT at
   `/sf-console.vv`. Kerbside verifies the signature, `aud`, and `exp`
   entirely offline against per-source signing keys cached in
   `sf_token_keys` — it never calls the cloud on the exchange path (only a
   single refetch on an unknown key id, to tolerate rotation). Single use is
   enforced by recording each token's `jti` in `sf_token_jtis`, so a replayed
   token is rejected.
6. **Audit Logging**: All console access events recorded

## Monitoring

The Rust proxy exports Prometheus metrics on a configurable port (default
13003), bound to `--metrics-address` (loopback by default). The registered
metrics are:

- `kerbside_proxy_connections_total` / `kerbside_proxy_active_connections`
- `kerbside_proxy_authorized_total` / `kerbside_proxy_denied_total`
- `kerbside_proxy_bytes_relayed_total{direction}`
- `kerbside_proxy_firewall_verdicts_total{...}`

## Directory Structure

```
kerbside/
  main.py              # Entry point, daemon management
  proxy_supervisor.py  # Launches/supervises the Rust proxy child
  api.py               # REST API
  db.py                # Database models and queries
  config.py            # Configuration management
  consoletoken.py      # Token generation/validation
  util.py              # Shared utilities
  rpc/                 # KerbsideProxy gRPC service (.proto, generated
                       #   stubs, servicer, UDS server)
  sources/             # Cloud source implementations
  api/                 # Web UI assets
    templates/         # Jinja2 templates: base.html (old Bootstrap base)
                       #   and base-sfui.html (new sfui base; see AGENTS.md)
    static/            # CSS, JS, icons
      sfui/            # Vendored shakenfist/sfui design system (never
                       #   edited in place; see docs/development.md)
rust/kerbside-proxy/   # The Rust SPICE proxy (binary crate)
  src/                 # listeners, TLS, handshake, backend leg, relay,
                       #   firewall (policy.rs/allowlist.rs), gRPC client
alembic/               # Database migrations
  versions/            # Migration scripts
etc/                   # Configuration examples
tools/                 # Utility scripts (incl. run-tempest-tests)
  direct-qemu/         # Direct-QEMU CI lane glue scripts (phase 5+)
    generate-tls.sh    # Mint ephemeral self-signed CA + proxy cert
    start-qemu.sh      # Launch a QEMU guest with SPICE + OVMF
    start-kerbside.sh  # Start gunicorn API + kerbside daemon run
    smoke-client.py    # Control-socket smoke test (hello/status/screenshot)
    lane-up.sh         # Top-level lane orchestrator
    lane-down.sh       # Best-effort lane teardown
    run-scenario.sh    # Install tempest + plugin into a venv, write
                       #   tempest.conf, run test_sextant_scenario —
                       #   last step in the direct-qemu workflow
    rebuild-sextant-qcow2.sh  # Developer tool: refresh Sextant qcow2
  sf-e2e/              # Shaken Fist end-to-end CI lane (phase 9): drive a
                       #   real SF cluster + co-located kerbside
    provision-sf.sh    # Set KERBSIDE_URL + signing key, restart sf-api
    gen-sources.py     # Write the type: shakenfist sources.yaml
    deploy-kerbside.sh # Build ryll, venv-install kerbside, reuse
                       #   direct-qemu/start-kerbside.sh on the primary
    import-instance.sh # Upload Sextant, boot a UEFI+SPICE SF instance
    drive-happy-path.py    # Mint → verify → exchange → proxied session
    drive-adversarial.py   # replay/expired/aud/kid/cross-namespace
    gather-artifacts.sh    # Collect logs from the primary (no token)
  ovirt-e2e/           # oVirt end-to-end CI lane (two-tier CI phase 1):
                       #   deploy the PR's kerbside on the runner against
                       #   a live oVirt 4.5 engine, relay a proxied
                       #   SPICE session with host_subject pinning
    gen-sources.py     # Write the type: ovirt sources.yaml (engine CA
                       #   fetched and embedded inline)
    deploy-kerbside.sh # Venv-install kerbside + proxy wheel, reuse
                       #   direct-qemu/start-kerbside.sh, wait for the
                       #   source to be healthy
    drive-console.py   # Scrape → .vv → ryll → smoke client → TLS/pinning
                       #   log oracles → live REST terminate
tests/
  fixtures/            # Committed test fixtures
    uncalibrated-sextant.qcow2  # Sextant UEFI guest image for CI
tempest-plugin/        # Kerbside Tempest plugin (separate releasable)
  kerbside_tempest_plugin/
    ryll_client.py     # Stdlib NDJSON control-socket client
    config.py          # [kerbside] tempest options incl. scenario opts
    tests/
      api/             # OpenStack lane tests (require live cloud)
      scenario/        # Direct-qemu scenario tests (skip when
                       #   control_socket_path unset — drop-in safe)
loadtests/             # Load testing tools
  latency/             # Latency loadtest (orchestrator.py + Dockerfile)
docs/                  # Operator, developer, and protocol documentation
  spice/               # SPICE protocol reference
  use-cases/           # Per-deployment operator guides (oVirt today)
  plans/               # Point-in-time plan records, not living docs
```

## Sextant Scenario Test

The tempest plugin contains an end-to-end scenario test
(`tests/scenario/test_sextant_scenario.py`) that drives the Uncalibrated
Sextant UEFI guest through the full Awaiting → Booting → bootloader-ignore →
paste → Parked → shutdown sequence. It connects to Ryll's control socket
(protocol v1.1), sends keypresses and a paste payload, and asserts two
independent oracles: the live `digest_updated` QR event stream and the
post-mortem serial drain. The test requires Ryll built with
`--features digest-decode`; the direct-qemu workflow enables that feature.

The test skips when `CONF.kerbside.control_socket_path` is unset, keeping the
plugin drop-in safe on the OpenStack lane. On the direct-qemu lane
`tools/direct-qemu/run-scenario.sh` sets all four `[kerbside]` tempest
options (`control_socket_path`, `serial_log_path`, `scenario_artifact_dir`,
`scenario_step_timeout`) and runs the test as the final lane step. The final
keypress causes Sextant to drain its event ring to serial and ACPI-shutdown,
which terminates qemu and unlinks the control socket — nothing in the lane
is usable afterwards.

## Related Documentation

For detailed SPICE protocol documentation, see the
[docs/](docs/index.md) directory:

- [Protocol Overview](docs/spice/protocol-overview.md) - SPICE protocol fundamentals
- [Channel Protocols](docs/spice/channel-protocols.md) - Per-channel message formats
- [Capabilities](docs/spice/capabilities.md) - Feature negotiation
- [Proxy Architecture](docs/proxy-architecture.md) - Internal proxy design details
- [Use Cases](docs/use-cases/ovirt.md) - Per-deployment operator guides
