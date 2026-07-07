# Verifying session termination (phase 5)

Phase 5 makes API-driven session termination drop in-flight SPICE
connections. In production the REST API writes a `session_terminations`
intent row, each proxy node's daemon polls it and pushes a
`TerminateSession` over the local `ProxyControl` gRPC stream, and the
Rust proxy cancels every channel of that session. This harness proves
the proxy end of that path live, without a full daemon+API+DB stack, by
having the standalone mock gRPC server emit the `TerminateSession`.

## Driving it

`mock-grpc-server.py --terminate-after-seconds N` (or
`MOCK_GRPC_TERMINATE_AFTER=N`) makes the mock's `ProxyControl` stream
emit a one-shot `TerminateSession(session_id)` **N seconds after the
first client authorization** — so it fires while a client is reliably
connected, regardless of when the client connects relative to the proxy
starting.

```
export WORKDIR=/tmp/k5term
export MOCK_GRPC_PYTHON="$PWD/.tox/py3/bin/python" PYTHONPATH="$PWD"
export RUST_PROXY_BINARY="$PWD/rust/kerbside-proxy/target/release/kerbside-proxy"
export MOCK_GRPC_TERMINATE_AFTER=15
tools/direct-qemu/verify-rust-proxy.sh up
remote-viewer "$WORKDIR/console.vv"        # connects; 15s later it is dropped
# ... the client is disconnected; then:
tools/direct-qemu/verify-rust-proxy.sh down
```

A clean result is visible in the proxy log (`$WORKDIR/rust-proxy.log`):
the proxy receives the event and the registry matches the session, then
every channel's relay tears down.

## Live capture RESULTS

Run 2026-07-08 (proxy release binary at ryll pin `1c6f19f`, phase-5
branch), `uncalibrated-sextant.qcow2` guest under qemu (TCG),
`MOCK_GRPC_TERMINATE_AFTER=15`, `remote-viewer` client.

- `authorized_total=4` — remote-viewer established the 4 core channels
  (main, display, inputs, cursor).
- 15 s after the first authorization the mock emitted
  `TerminateSession(session_id=rust-proxy-verify-session)`. The proxy
  logged:
  - `ProxyControl TerminateSession event … session_id=rust-proxy-verify-session terminated=true`
    (the event was received and the session was found in the registry), and
  - four `session terminated by control plane; ending relay` lines, one
    per channel (`display`, `cursor`, `inputs`, `main`).
- `remote-viewer` was disconnected (its process exited) as its streams
  closed. **PASS**: a live, connected session was dropped by a
  control-plane `TerminateSession`.

(A `/metrics` `active_connections` sampler is a poor oracle here: all
four relays end simultaneously, so a coarse poll can miss the
connected window. The proxy log — `terminated=true` plus one
`ending relay` per channel — is the definitive signal.)

## Covered by unit tests (not this live run)

The Python half of the bridge — the `session_terminations` table, the
API writing the intent, `ProxyControl` selecting the sessions live on
this node and pushing them, and the TTL reaper — is covered by the
`kerbside/tests/unit` suite. The full daemon+API+MariaDB path (as
opposed to the mock emitting the event) is exercised by those unit
tests plus, ultimately, the phase-7 CI lane; a deterministic headless
client (ryll) is the natural driver there.
