# Kerbside Proxy Architecture

This document provides a detailed technical description of Kerbside's proxy
architecture, including the connection state machine, process model, and traffic
handling.

> **Note:** the SPICE proxy is the Rust `kerbside-proxy`
> (`rust/kerbside-proxy/`), which relays over async tokio tasks and consults
> the control-plane gRPC service for authorization. The **connection state
> machine, SPICE handshake, channel model, and traffic-handling concepts**
> below still describe how the proxy works; the **implementation specifics**
> in the earlier sections (the `multiprocessing.Process` worker pool, the
> `SpiceSession`/`session.run` Python classes) describe the original Python
> proxy, which was **removed at cutover**, and are retained here as protocol
> and design background. For the current implementation see `ARCHITECTURE.md`
> (the summary), `rust/kerbside-proxy/src/`, and
> `docs/plans/PLAN-rust-proxy.md`. The "Process model" and "Session
> termination" sections below are current (Rust). A full rewrite of the
> earlier internals sections in Rust terms is tracked as follow-up work.

## Process Architecture

Kerbside uses a multiprocess architecture for scalability and isolation:

```
+---------------------------+
|    kerbside-daemon        |  Main daemon process
|    (main.py)              |  - Spawns proxy subprocess
|                           |  - Runs maintenance loop
+-------------+-------------+
              |
              | Subprocess
              v
+---------------------------+
|    kerbside-proxy         |  Proxy manager process
|    (proxy.py:run)         |  - Accepts connections
|                           |  - Spawns workers
+-------------+-------------+
              |
              | multiprocessing.Process
              v
+---------------------------+
|    kerbside-secure-*      |  Worker processes (one per connection)
|    (SpiceTLSSession)      |  - Handles single SPICE channel
|                           |  - Bidirectional proxy
+---------------------------+
```

### Benefits of Multiprocess Architecture

1. **Isolation**: Each connection runs in its own process, preventing one
   misbehaving connection from affecting others.

2. **Resource Management**: Workers can be killed individually if they become
   unresponsive or consume excessive resources.

3. **Simplicity**: No complex threading or async I/O required; each worker uses
   simple blocking I/O with `select()`.

4. **Observability**: Process names reflect connection state, making monitoring
   easier (e.g., `kerbside-secure-abc123-display-0`).

## Connection Listener

The `SpiceListener` class manages incoming connections:

```python
class SpiceListener:
    def __init__(self, address, port, tls_port):
        # Insecure port (5901) - redirects to TLS
        self.unsecured = socket.socket(...)
        self.unsecured.bind((address, port))

        # Secure port (5900) - TLS-wrapped connections
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(cert_path, key_path)
        self.secured = socket.socket(...)
        self.secured.bind((address, tls_port))
```

### TLS Configuration

- Server certificate and key loaded from configured paths
- CA certificate loaded for client verification (optional)
- Default verify paths configured for system CAs

## Connection State Machine

### Insecure Connection Flow (SpiceSession)

Connections to the insecure port (5901) follow a simple flow:

```
     Accept Connection
            |
            v
    +---------------+
    | Receive Data  |
    +-------+-------+
            |
            v
    +---------------+
    | Parse Client  |
    | SpiceLinkMess |
    +-------+-------+
            |
            v
    +---------------+
    | Send Reply    |
    | need_secured  |
    +-------+-------+
            |
            v
    +---------------+
    | Close         |
    +---------------+
```

This redirects clients to use TLS on port 5900.

### Secure Connection Flow (SpiceTLSSession)

TLS connections follow a more complex state machine:

```
     Accept TLS Connection
            |
            v
    +-------------------+
    | ClientSpiceLinkMess|  Parse client hello, send server hello
    +--------+----------+
             |
             v
    +-------------------+
    | ClientPassword    |  Decrypt token, validate, connect to hypervisor
    +--------+----------+
             |
             v
    +-------------------+
    | ClientProxy       |  Bidirectional traffic relay
    | ServerProxy       |
    +-------------------+
```

### State Handlers

Each state is implemented as a method that returns the number of bytes consumed:

```python
class SpiceTLSSession:
    def __init__(self, ...):
        self.client_next_packet = self.ClientSpiceLinkMess  # Initial state
        self.server_next_packet = None

    def ClientSpiceLinkMess(self, buffered):
        # Parse client hello
        # Generate RSA keypair
        # Send server hello with public key
        self.client_next_packet = self.ClientPassword
        return bytes_consumed

    def ClientPassword(self, buffered):
        # Decrypt token
        # Validate against database
        # Connect to hypervisor
        self.client_next_packet = self.ClientProxy
        self.server_next_packet = self.ServerProxy
        return bytes_consumed

    def ClientProxy(self, buffered):
        # Parse and forward client traffic to server
        return bytes_consumed

    def ServerProxy(self, buffered):
        # Parse and forward server traffic to client
        return bytes_consumed
```

## Main Processing Loop

The main processing loop uses non-blocking I/O with `select()`:

```python
def run(self):
    client_buffered = bytearray()
    server_buffered = bytearray()

    while True:
        sockets = [self.client_conn]
        if self.server_conn:
            sockets.append(self.server_conn)

        # Wait for data (0.2 second timeout)
        readable, _, errors = select.select(sockets, [], sockets, 0.2)

        # Read available data
        for r in readable:
            if r == self.client_conn:
                client_buffered += self.client_conn.recv(1024000)
            elif r == self.server_conn:
                server_buffered += self.server_conn.recv(1024000)

        # Process buffered data
        if client_buffered:
            consumed = self.client_next_packet(client_buffered)
            while consumed > 0:
                client_buffered = client_buffered[consumed:]
                consumed = self.client_next_packet(client_buffered)

        if self.server_next_packet and server_buffered:
            consumed = self.server_next_packet(server_buffered)
            while consumed > 0:
                server_buffered = server_buffered[consumed:]
                consumed = self.server_next_packet(server_buffered)
```

### Why 0.2 Second Timeout?

The short timeout ensures responsive handling even when:
- State transitions occur that enable new packet processing
- One socket becomes readable while processing the other
- Clean shutdown needs to occur

## Packet Parsing Pattern

All packet parsers follow a consistent pattern:

```python
def parse_packet(buffered):
    # Check minimum header size
    if len(buffered) < HEADER_SIZE:
        return 0  # Need more data

    # Parse header
    message_type, message_size = struct.unpack_from('<HI', buffered)

    # Check if complete message is available
    if len(buffered) < HEADER_SIZE + message_size:
        return 0  # Need more data

    # Process message
    # ...

    # Return bytes consumed
    return HEADER_SIZE + message_size
```

This pattern enables:
- Partial packet handling (wait for more data)
- Multiple packets in one read (process in loop)
- Clean separation of concerns

## Traffic Inspection

Kerbside can optionally inspect and log all traffic:

### Inspector Architecture

```python
class InspectableTraffic:
    def configure_inspection(self, source, uuid, session_id, channel):
        if config.TRAFFIC_INSPECTION:
            self.logfile = open(...)

    def emit_entry(self, entry):
        if config.TRAFFIC_INSPECTION:
            self.logfile.write(f'{timestamp} {entry}\n')
```

### Channel-Specific Inspectors

Each channel type has dedicated inspectors:

| Channel | Client Inspector | Server Inspector |
|---------|------------------|------------------|
| main    | ClientMainPacket | ServerMainPacket |
| display | ClientDisplayPacket | ServerDisplayPacket |
| inputs  | ClientInputsPacket | ServerInputsPacket |
| cursor  | ClientCursorPacket | ServerCursorPacket |
| port    | ClientPortPacket | ServerPortPacket |

### Intimate Logging

With `TRAFFIC_INSPECTION_INTIMATE` enabled, detailed data is logged:
- Keystrokes and scancodes
- Mouse coordinates and button states
- Image frame data

This creates audit trails but should be used carefully due to privacy
implications.

## ACK Handling for Inserted Packets

When traffic inspection modifies packets (e.g., adding border frames),
the proxy must handle acknowledgements correctly:

```python
def ClientProxy(self, buffered):
    pt = self.client_parser(buffered)

    if pt.inserted_packets > 0:
        # We inserted packets that server will ACK
        self.server_ignore_acks += pt.inserted_packets

    if pt.packet_is_ack and self.client_ignore_acks > 0:
        # This ACK is for a packet we inserted, don't forward
        self.client_ignore_acks -= 1
    else:
        self.server_conn.sendall(pt.data_to_send)
```

## Worker Management

The proxy manager monitors and manages worker processes:

### Worker Tracking

```python
workers = []

for conn, client_host, client_port, secured in listen.accept():
    session = SpiceTLSSession(conn, client_host, client_port)
    p = multiprocessing.Process(target=session.run, ...)
    p.start()
    workers.append(p)
```

### Worker Cleanup

Every second, the proxy manager:

1. **Identifies stray processes**: Workers older than 5 seconds without
   database channel records
2. **Terminates strays**: Sends SIGKILL to unregistered workers
3. **Reaps terminated workers**: Joins completed processes and removes
   database records

```python
# Find strays
for child in psutil.Process(os.getpid()).children():
    if child.pid not in channel_pids:
        if time.time() - child.create_time() > 5:
            os.kill(child.pid, signal.SIGKILL)

# Reap terminated
for p in workers:
    if not p.is_alive():
        p.join(1)
        db.remove_proxy_channel(config.NODE_NAME, p.pid)
```

## Database State

Worker processes register their state in the database:

### Channel Info Recording

```python
db.record_channel_info(
    node_name,
    pid,
    client_ip=...,
    client_port=...,
    connection_id=...,
    channel_type=...,
    channel_id=...,
    session_id=...
)
```

This enables:
- Cross-process monitoring
- Admin UI session display
- Cleanup of orphaned records

## Prometheus Metrics

Workers report metrics via a shared queue:

```python
# In worker
self.prometheus_updates.put(('bytes_proxied', labels, byte_count))

# In manager
while True:
    name, labels, value = prometheus_updates.get(block=False)
    if name == 'bytes_proxied':
        bytes_proxied.labels(**labels).inc(value)
```

### Exported Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| workers | Gauge | - | Number of active workers |
| bytes_proxied | Counter | type, session_id | Bytes transferred |
| proxy_time | Counter | type, session_id | Processing time |

## Error Handling

### Connection Errors

| Error | Handling |
|-------|----------|
| BadMagic/BadMajor/BadMinor | Terminate connection |
| HandshakeFailed | Terminate connection |
| ConnectionRefused | Log, terminate |
| BrokenPipeError | Log, cleanup sockets |
| ConnectionResetError | Log, cleanup sockets |

### SSL Errors

SSL read errors are handled gracefully:

```python
try:
    d = self.client_conn.recv(1024000)
except ssl.SSLWantReadError:
    # SSL layer has no data, continue loop
    pass
```

## Security Considerations

### Token Validation

All connections must present valid tokens:
- Tokens are time-limited (configurable expiry)
- Tokens are single-use (prevent replay attacks)
- Invalid tokens result in immediate disconnection

### Audit Logging

All significant events are logged:
- Channel creation
- Hypervisor connection success/failure
- Token validation results
- Traffic inspection events (if enabled)

### Process Isolation

Each connection runs in its own process:
- Memory isolation between connections
- Independent crash handling
- Resource limits can be applied per-process

## Rust Proxy: the SPICE Firewall

The Python proxy above relays post-authentication traffic opaquely; the
Rust proxy's relay (`rust/kerbside-proxy/src/relay.rs`) is inspection-first
instead, framing every message by its 6-byte `MessageHeader` and passing it
through a `Policy` before forwarding. As of phase 4 (see
`docs/plans/PLAN-rust-proxy-phase-04-firewall.md`), that policy is
`EnforcingPolicy` (`policy.rs`): a real, enforcing application-level SPICE
firewall, on by default.

### Per-message pipeline

For every framed message the relay's `pump` runs:

1. **Header parse.** The 6-byte header (`message_type: u16`,
   `message_size: u32`) is parsed first; nothing below inspects the body
   until this succeeds.
2. **`Policy::check_header` (L0, pre-body).** Called exactly once per
   message, before its body is buffered, so an over-cap or over-rate
   message is refused without ever accumulating it:
   - a per-(channel, direction) **size cap** — tight (4 KiB) on the
     inputs-client and cursor-client directions (key/mouse events are
     small and fixed), generous (16 MiB) everywhere else (the display
     server bulk direction and any channel with no modeled grammar);
   - a coarse per-direction **rate/throughput ceiling** (fixed window),
     disabled by default — a deployment can opt in once real traffic
     patterns justify a value.

   These policy caps sit below the relay's own unconditional
   `MAX_MESSAGE_SIZE` (16 MiB) absolute frame guard, which the relay
   enforces unconditionally regardless of policy — a peer that claims an
   absurd `message_size` is refused before the relay would buffer
   gigabytes waiting for a body that never arrives.
3. **`Policy::inspect` (L1).** Once the full body has been buffered, the
   message type is classified against a compiled-in per-channel,
   per-direction allowlist (`allowlist.rs`), derived from the ryll
   `shakenfist-spice-protocol` name tables unioned with the SPICE
   common-base opcodes (server `SPICE_MSG_*` 1..=7, client `SPICE_MSGC_*`
   1..=6, valid on every channel). Main, display, inputs, cursor, and
   playback have their own tables; usbredir/port/webdav ride the spicevmc
   table. **Record, smartcard, and tunnel have no modeled grammar** — they
   classify as `ChannelUnmodeled` and get L0-only enforcement plus
   observe-only handling for their message types (never a type-based
   terminate), rather than treating every type on those channels as a
   violation.
4. **Verdict.** `Forward` (write the original framed bytes unchanged) or
   `Terminate` (flush and end the whole relay — a single SPICE channel is
   one duplex TCP connection, so either direction ending ends the
   session). `Drop` is a variant on the `Verdict` enum reserved for future
   L2/L3 use (e.g. defanging); no v1 rule emits it, because silently
   dropping a mid-stream SPICE message would desynchronise the channel.

### Warn-only mode

`FirewallPolicy.mode` (`EnforcementMode::Enforce` default, or `WarnOnly`)
is the single place the enforcement decision is made
(`EnforcingPolicy::apply`). In `Enforce`, a rule's blocking verdict is
applied and recorded `action=enforced`. In `WarnOnly`, the SAME blocking
verdict is downgraded to `Forward` — the session is never actually
blocked — but still recorded `action=observed` plus a `tracing::warn!`.
This lets an operator run real traffic through a deployment and see
exactly what `Enforce` would have tripped before switching to it; it is a
mode, not a grace period, since the compiled default ships `Enforce`.

A forbidden **channel type** (a whole channel the deployment's
`FirewallPolicy.permitted_channels` excludes) is denied earlier, in
`session.rs`, before any relay is set up — a protocol-correct
`PermissionDenied` to the client plus an audit event, the same shape as
the existing unknown-channel-type rejection.

### Audit and metrics

Firewall violations must not become one audit event per message — a
hostile or broken peer could otherwise flood the audit log. Instead, both
relay directions share one lock-free per-connection `VerdictTally` (atomic
counters keyed by `(rule, action)`); `relay::run` reads it once after the
two pumps finish and, if anything was recorded, emits a single coalesced
summary `RecordAuditEvent` for the whole connection (e.g. "Firewall
verdicts this connection: disallowed_type (enforced=2, observed=0)").
Every verdict is also exported live as the Prometheus counter
`kerbside_proxy_firewall_verdicts_total{channel,direction,rule,action}`,
where `rule` is one of `disallowed_type`, `unmodeled_type`, `size_cap`, or
`rate_cap`, and `action` is `enforced` or `observed`.

### Policy delivery

Python continues to own policy; the Rust proxy only enforces it
("Python decides policy; Rust enforces it"). The tunable knobs — mode and
permitted channels — are delivered per-connection in the
`AuthorizeConnection` gRPC reply as a `FirewallPolicy` protobuf message,
built from Python's `FIREWALL_MODE`/`FIREWALL_PERMITTED_CHANNELS` config
(see `docs/configuration.md`). The L1 allowlist tables themselves are
**not** delivered over gRPC: which message types are structurally valid on
a channel is a fact about the SPICE protocol, not a deployment policy, so
they are compiled into the proxy. Size caps, the rate ceiling, and
per-verdict severities keep their compiled defaults in v1 (no gRPC config
surface yet).

Out of scope for phase 4, and not yet implemented anywhere in the Rust
proxy: L2 body validation (scancode ranges, clipboard/file-transfer/
usbredir device-class filtering), session recording, and L3
rewriting/injection.

## Rust Proxy: Process Supervision and Session Termination

Phase 5 (`docs/plans/PLAN-rust-proxy-phase-05-daemon-integration.md`) makes
the Python daemon able to **run** the Rust proxy, and makes API-driven
session termination actually drop in-flight connections rather than only
blocking new ones.

### Process model: the daemon supervises the Rust proxy as a child

`kerbside daemon run` supervises the Rust proxy binary as a child:

```
+---------------------------+
|    kerbside-daemon        |  main.py:daemon_run
|    (main.py)               |  - binds the gRPC UDS server FIRST
+-------------+-------------+
              |
              | subprocess.Popen
              v
+---------------------------+
|    kerbside-proxy         |  the Rust binary (rust/kerbside-proxy/)
|    (async tokio tasks)    |  - dials the gRPC UDS at startup
+---------------------------+  (ClearNodeChannels) and lazily thereafter
```

- The gRPC UDS server is bound **before** the child is launched, because
  the Rust proxy dials it at startup and would fail if the socket did not
  yet exist. (A subprocess child, unlike a fork, does not inherit the gRPC
  server's fds/threads.)
- `kerbside/proxy_supervisor.py`'s `find_proxy_bin()` resolves the binary
  (env `KERBSIDE_PROXY_BIN` → `PATH` → the in-repo `target/{release,debug}`
  dev build dir) and `build_proxy_argv()` maps config to the proxy's CLI
  flags (`--vdi-address`, `--secure-port`, `--cert`, `--metrics-address`,
  etc.) — the firewall knobs are excluded, since those are delivered
  per-connection over gRPC (see the firewall section above), not on the
  command line.
- The daemon polls the child's liveness every second (mirroring the
  Python-proxy fork's supervision loop) and forwards SIGTERM with a
  15-second deadline before SIGKILLing it; exits non-zero if the child
  dies unexpectedly. The 15-second deadline is sized above the proxy's own
  10-second graceful-drain window (below), so the daemon gives the proxy a
  chance to drain before forcing it.

### How the binary gets there: packaging (phase 6)

`find_proxy_bin()`'s middle leg — `shutil.which('kerbside-proxy')` — is
what resolves the binary in a real deployment, and phase 6 is what makes
that leg succeed. The crate is published to PyPI as a separate
`kerbside-proxy` package: a maturin `bindings = "bin"` wheel
(`rust/kerbside-proxy/pyproject.toml`) whose compiled binary is laid into
the wheel's `*.data/scripts/` directory, which pip installs onto `PATH`.
`kerbside` exact-pins `kerbside-proxy` at the same version, so `pip install
kerbside` transitively installs a matching proxy and the gRPC contract
matches by construction.

The two packages are released in lockstep from a single `v*` tag:
`setuptools_scm` gives `kerbside` its version, and
`tools/stamp-proxy-version.sh` stamps that same version into the crate
(for maturin) and into the `kerbside` dependency pin.
`tools/build-proxy-wheel.sh` builds prebuilt manylinux_2_28 wheels for
**x86_64 and aarch64** (the latter cross-compiled with maturin `--zig`, so
no aarch64 build host is required); no source distribution is published, so
an unsupported platform gets a clean pip error rather than a doomed source
build. In development you bypass all of this: `find_proxy_bin()` falls
through to the in-repo `cargo build` output, or you set
`KERBSIDE_PROXY_BIN` explicitly. See
`docs/plans/PLAN-rust-proxy-phase-06-packaging.md` and `RELEASE-SETUP.md`.

### Session termination: dropping in-flight connections

Before phase 5, `ConsolesTerminate`/`SessionTerminate` only removed or
expired the DB token, which blocks a **new** connection attempt; a client
already connected kept its channels open until it disconnected itself —
there was no path from "the API terminated this session" to "the proxy
holding that session's sockets finds out".

**The distributed-deployment constraint.** Kerbside can run with the REST
API and the proxy processes on different machines (the proxy is often
sized separately from the API), and proxies can sit behind a load balancer
so that different channels of the *same* session land on *different* proxy
nodes. The only component every one of these can reach is the shared
MariaDB — there is no API→proxy or proxy→proxy RPC across machines. The
`ProxyControl` gRPC stream, by contrast, is strictly **local**: one stream
between a daemon and the single proxy it supervises on the same host, over
the same UDS as every other RPC in the table above. Termination therefore
has to be a DB-mediated intent that each node acts on independently for
the channels it happens to hold:

```
REST API                         Proxy node A              Proxy node B
(may be elsewhere)                (holds channels           (holds other
                                    1,2 of session S)         channels of S)
    |                                   |                          |
    | INSERT session_terminations(S)    |                          |
    v                                   |                          |
+----------+                            |                          |
| MariaDB  | <--- polls get_terminations_for_node("A") ------------+
| (only    | <--- polls get_terminations_for_node("B") -------------------+
|  shared  |                            |                          |
|  bus)    |                            |                          |
+----------+                            |                          |
                                         v                          v
                              ProxyControl: TerminateSession(S)   ...same...
                                         |
                                         v
                          Rust proxy: SessionRegistry.terminate(S)
                                         |
                                         v
                    relay::run's select! sees token.cancelled() -> teardown
                    (once per channel this node holds -- here, 2 relays end)
```

Concretely:

1. **API** (`api.py`, `ConsolesTerminate`/`SessionTerminate`): keeps the
   existing token expire/remove and additionally calls
   `db.request_session_termination(session_id, reason)`, which
   upserts a row into the new `session_terminations` table
   (`session_id` primary key, `requested_at`, optional `reason`; migration
   `c4e7a1b9d2f3`). Idempotent — re-terminating an already-terminated
   session just refreshes `requested_at`.
2. **Daemon** (`servicer.py::ProxyControl`, one stream per local proxy):
   each poll interval, calls `db.get_terminations_for_node(NODE_NAME)` —
   an intersection of `session_terminations` with this node's live
   `proxychannels` rows — and yields a `TerminateSession(session_id)` for
   every id not already sent on this stream, interleaved with `Heartbeat`s
   so the stream stays alive between events. A DB error is logged and the
   loop continues rather than killing the stream. Natural token *expiry*
   (no explicit termination) is never pushed — this matches the Python
   proxy's existing behaviour, where expiry only blocks new connections.
3. **Rust proxy** (`session.rs::SessionRegistry`, `rpc.rs::
   run_proxy_control`): a `Mutex<HashMap<session_id, CancellationToken>>`
   refcounted across the session's live channels (one entry per session,
   incremented on each channel's registration, decremented and removed on
   the last channel's teardown). Receiving `TerminateSession` cancels the
   token; `relay.rs`'s `select!` gained a third arm on
   `token.cancelled()` alongside the two pumps, so every channel of the
   session this node holds tears down cleanly (no error, same shape as a
   protocol-level `Terminate` verdict) and the client is disconnected.
   Cancelling an unknown or already-torn-down session is a no-op, so a
   late or duplicate push (another node's poll cycle, a retry) is safe.
4. **Reaper** (daemon maintenance loop, `reap_session_terminations`):
   deletes `session_terminations` rows older than 5 minutes — long past
   the point every node has polled and acted — keeping the table small.

A merely-expired (not explicitly terminated) token is never pushed as a
`TerminateSession`, so natural token expiry does not tear a live session
down mid-use — only an explicit API terminate does.

### Graceful drain on shutdown

On SIGTERM, the proxy's `shutdown_signal` future resolving triggers the
same teardown path used for termination: it stops the listeners from
accepting new connections, then calls `SessionRegistry::terminate_all()`
(cancelling every live session's token at once) and waits up to a
10-second deadline for the active-connection count (the same gauge behind
`/metrics`) to reach zero before returning. The 10-second drain deadline is
deliberately shorter than the daemon's 15-second SIGTERM-to-SIGKILL window
above it, so a supervised restart lets in-flight sessions finish tearing
down on their own terms rather than being cut off mid-drain by the
daemon's SIGKILL.

### Verifying it live

`tools/direct-qemu/VERIFY-TERMINATION.md` drives this end to end against a
real client: the mock gRPC server's `ProxyControl` stream emits a one-shot
`TerminateSession` a configurable number of seconds after the first
authorization (`MOCK_GRPC_TERMINATE_AFTER`), standing in for the
API→DB→daemon-poll leg so the harness can exercise just the proxy side
live. A recorded run against `remote-viewer` shows all four of its
channels (main, display, inputs, cursor) torn down by a single
`TerminateSession` event.

## Related Documentation

- [Protocol Overview](protocol-overview.md) - SPICE protocol introduction
- [Link Protocol](spice-link-protocol.md) - Connection handshake details
- [Channel Protocols](channel-protocols.md) - Per-channel message formats
