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
- Runs a maintenance loop every 60 seconds to:
  - Refresh console listings from configured sources
  - Reap expired authentication tokens
  - Handle source configuration changes

### 2. Proxy Layer (`proxy.py`)

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

### 3. API Layer (`api.py`)

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

### 4. SPICE Protocol Layer (`spiceprotocol/`)

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

### 5. Database Layer (`db.py`)

SQLAlchemy ORM with Alembic migrations. Uses MySQL/MariaDB.

**Tables:**

| Table | Purpose |
|-------|---------|
| `sources` | Cloud source configurations |
| `consoles` | Discovered VM consoles |
| `consoletokens` | Authentication tokens with expiry |
| `proxychannels` | Active proxy connections |
| `auditevents` | Activity logging |

### 6. Source Abstraction (`sources/`)

Pluggable console discovery from different cloud platforms.

**Implementations:**

| Source | File | Description |
|--------|------|-------------|
| Shaken Fist | `shakenfist.py` | Uses `shakenfist_client` library |
| oVirt | `ovirt.py` | Uses `ovirtsdk4` library |
| OpenStack | `api.py` | On-demand via Nova token validation |

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
  sources/             # Cloud source implementations
  api/                 # Web UI assets
    templates/         # Jinja2 templates
    static/            # CSS, JS, icons
alembic/               # Database migrations
  versions/            # Migration scripts
etc/                   # Configuration examples
tools/                 # Utility scripts (incl. run-tempest-tests)
tempest-plugin/        # Kerbside Tempest plugin (separate releasable)
testclient/            # Ryll test client
loadtests/             # Load testing tools
docs/                  # Protocol documentation
```

## Related Documentation

For detailed SPICE protocol documentation, see the [docs/](docs/) directory:

- [Protocol Overview](docs/protocol-overview.md) - SPICE protocol fundamentals
- [Channel Protocols](docs/channel-protocols.md) - Per-channel message formats
- [Capabilities](docs/capabilities.md) - Feature negotiation
- [Proxy Architecture](docs/proxy-architecture.md) - Internal proxy design details
