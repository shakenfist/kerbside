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
