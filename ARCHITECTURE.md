# Kerbside Architecture

Kerbside is a SPICE VDI protocol proxy written in Python that provides remote
console access to VMs running in virtualization clusters (Shaken Fist,
OpenStack, oVirt). It acts as a protocol-native proxy that terminates client
SPICE connections, identifies which VM to proxy to based on authentication
tokens, and relays traffic bidirectionally between client and server.

## High-Level Architecture

```
                                    +------------------+
                                    |   Web Browser    |
                                    |   (Admin UI)     |
                                    +--------+---------+
                                             |
                                             | HTTPS
                                             v
+------------------+              +----------+---------+
|  SPICE Client    |    TLS      |                    |
|  (virt-viewer)   +------------>+   Kerbside Proxy   |
+------------------+   :5900     |                    |
                                 |  +-------------+   |
                                 |  | API Layer   |   |
                                 |  | (Flask)     |   |
                                 |  +-------------+   |
                                 |  | Proxy Layer |   |
                                 |  | (Workers)   |   |
                                 |  +-------------+   |
                                 |  | Protocol    |   |
                                 |  | Layer       |   |
                                 |  +-------------+   |
                                 +---------+----------+
                                           |
                    +----------------------+----------------------+
                    |                      |                      |
                    v                      v                      v
           +-------+-------+      +-------+-------+      +-------+-------+
           | Shaken Fist   |      |   OpenStack   |      |     oVirt     |
           | Hypervisors   |      |   Hypervisors |      |   Hypervisors |
           +---------------+      +---------------+      +---------------+
```

## Core Components

### 1. Main Process (`main.py`)

The main entry point orchestrates the system lifecycle:

- Parses source configuration from `sources.yaml`
- Spawns the proxy process as a subprocess
- Hosts the control-plane gRPC service (see below) on a background
  thread over a unix domain socket
- Runs a maintenance loop every 60 seconds to:
  - Refresh console listings from configured sources
  - Reap expired authentication tokens
  - Handle source configuration changes

### 2. Control-plane gRPC service (`rpc/`)

The `KerbsideProxy` gRPC service (`kerbside/rpc/kerbside.proto`,
servicer in `kerbside/rpc/servicer.py`, hosting in
`kerbside/rpc/server.py`) fronts the database operations the SPICE
proxy needs, so a separate proxy process can consult Python for
authorization and channel bookkeeping instead of accessing MariaDB
directly. This is the seam for the planned Rust proxy: Python keeps
owning the database and policy; the proxy consults this service.

It is exposed over a filesystem-guarded unix domain socket
(`API_SOCKET_PATH`, default `/run/kerbside/api.sock`) with insecure
gRPC credentials (the peer is a trusted local process), hosted on a
`ThreadPoolExecutor` in the daemon process. Errors are signalled via
gRPC status codes.

| RPC | Maps to | Purpose |
|-----|---------|---------|
| `AuthorizeConnection` | `get_token_by_token` + `get_source` + `get_console` | Resolve a decrypted token to a hypervisor `Target`, or `Denied`; records the session and the `Channel created` audit |
| `RegisterChannel` | `record_channel_info` | Pre-authorization channel record |
| `RecordAuditEvent` | `add_audit_event` | Write an audit event |
| `DeregisterChannel` | `remove_proxy_channel` | Remove a channel at teardown |
| `ClearNodeChannels` | `remove_node_channels` | Clear stale channel rows at proxy startup |
| `ProxyControl` (streaming) | — | Daemon→proxy control channel (session termination / policy push); a keepalive stub today, real events land with the Rust proxy work |

The `.proto` is compiled with `tox -egenprotos` (see
`tools/gen-protos.sh`); generated stubs are checked in under
`kerbside/rpc/`. Channel rows are keyed by a proxy-supplied
`connection_ref` on the `proxychannels` table (which now has a
surrogate `id` primary key), while the Python proxy continues to key
by `(node, pid)` until cutover.

### 3. Proxy Layer (`proxy.py`)

The proxy layer handles all SPICE protocol traffic using a multiprocess worker
pool architecture.

**Key Classes:**

| Class | Purpose |
|-------|---------|
| `SpiceListener` | Binds to secure (5900) and insecure (5901) ports, accepts connections |
| `SpiceSession` | Handles insecure connections, redirects to TLS |
| `SpiceTLSSession` | Main proxy logic for secure connections |

**Connection Flow:**

1. Client connects to port 5900 (TLS)
2. `SpiceListener` accepts and spawns worker process
3. `SpiceTLSSession` handles the connection state machine:
   - `ClientSpiceLinkMess()` - Parse client capabilities
   - `ClientPassword()` - Decrypt token, validate, lookup console
   - `ClientProxy()` / `ServerProxy()` - Bidirectional traffic relay

**Process Management:**

- Main proxy process monitors worker children using `psutil`
- Reaps terminated workers every 1 second
- Kills stray processes older than 5 seconds without active channels
- Updates Prometheus worker count metrics

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
| `GET /session` | List active proxy sessions |
| `GET /session/<id>/terminate` | Kill specific session |

### 5. SPICE Protocol Layer (`spiceprotocol/`)

Deep protocol handling for SPICE connections.

**Structure:**

```
spiceprotocol/
  __init__.py          # SpiceClient class
  packets/
    constants.py       # Channel mappings, error codes, capabilities
    linkmessages.py    # SPICE link protocol (handshake)
    authentication.py  # Auth packet handling
    main.py            # Main channel messages
    display.py         # Display channel messages
    inputs.py          # Input channel messages
    cursor.py          # Cursor messages
    port.py            # Port redirection
    inspection.py      # Traffic inspection framework
```

**Supported Channels:**

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

### 7. Source Abstraction (`sources/`)

Pluggable console discovery from different cloud platforms.

**Implementations:**

| Source | File | Description |
|--------|------|-------------|
| Shaken Fist | `shakenfist.py` | Uses `shakenfist_client` library |
| oVirt | `ovirt.py` | Uses `ovirtsdk4` library |
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
SpiceTLSSession decrypts and validates token
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
4. **Certificate Validation**: Host subject verification for hypervisor certs
5. **Audit Logging**: All console access events recorded

## Monitoring

Prometheus metrics exported on configurable port (default 13003):

- Worker process counts
- Connection statistics
- Traffic throughput
- Error rates

## Directory Structure

```
kerbside/
  main.py              # Entry point, daemon management
  proxy.py             # SPICE proxy implementation
  api.py               # REST API
  db.py                # Database models and queries
  config.py            # Configuration management
  consoletoken.py      # Token generation/validation
  util.py              # Shared utilities
  spiceprotocol/       # SPICE protocol handling
  rpc/                 # KerbsideProxy gRPC service (.proto, generated
                       #   stubs, servicer, UDS server)
  sources/             # Cloud source implementations
  api/                 # Web UI assets
    templates/         # Jinja2 templates
    static/            # CSS, JS, icons
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
docs/                  # Protocol documentation
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

For detailed SPICE protocol documentation, see the [docs/](docs/) directory:

- [Protocol Overview](docs/protocol-overview.md) - SPICE protocol fundamentals
- [Channel Protocols](docs/channel-protocols.md) - Per-channel message formats
- [Capabilities](docs/capabilities.md) - Feature negotiation
- [Proxy Architecture](docs/proxy-architecture.md) - Internal proxy design details
