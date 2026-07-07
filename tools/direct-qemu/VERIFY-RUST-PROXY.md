# Verifying the Rust proxy end to end

`kerbside-proxy` (the Rust SPICE proxy, `rust/kerbside-proxy/`) can be
verified end to end without MariaDB or the full Python daemon, using a real
qemu SPICE server, a small mock of the KerbsideProxy gRPC control service,
and a real SPICE client. This exercises the whole proxy path: TLS
termination, the SPICE link handshake, token decryption, the
`AuthorizeConnection` round trip over the unix socket, the backend connect to
the hypervisor, and the bidirectional inspection-first relay.

The full ryll-driven direct-qemu lane (with surface/digest assertions) is CI,
and lands in phase 7. This standalone harness is for local verification.

For validating the phase-4 L0/L1 **firewall** — running a safe warn-only
capture session and driving the connection-denial path — see
[`VERIFY-FIREWALL.md`](VERIFY-FIREWALL.md).

## Pieces

- `mock-grpc-server.py` — a standalone `KerbsideProxy` gRPC server on a unix
  socket that authorises every token and returns a `Target` pointing at the
  qemu SPICE port with the qemu ticket. It mirrors the real servicer's
  contract (`kerbside/rpc/servicer.py`) so the proxy cannot tell the
  difference. Run it with a Python that has `grpcio` installed and the
  `kerbside` package importable (`pip install -e .` or `PYTHONPATH=<repo>`).
- `start-rust-proxy.sh` — launches the built `kerbside-proxy` binary with the
  CI TLS material and the mock socket.
- `verify-rust-proxy.sh` — orchestrates qemu + mock + proxy (`up`), asserts
  relay activity via the proxy's Prometheus `/metrics` (`assert`), and tears
  everything down (`down`). The client step is pluggable: `remote-viewer
  <workdir>/console.vv` (GUI), or ryll headless + `smoke-client.py`.

Build the binary first (Docker, per the crate Makefile):
`make -C rust/kerbside-proxy build` (debug) or a `--release` build.

## The metrics assertion

After a client connects, `verify-rust-proxy.sh assert` polls
`http://127.0.0.1:<prometheus-port>/metrics` and requires
`kerbside_proxy_authorized_total >= 1` and
`kerbside_proxy_bytes_relayed_total > 0` for **both** the
`client_to_server` and `server_to_client` directions — i.e. a connection was
authorised and real SPICE traffic flowed in both directions through the
framed relay.

## Caveat: unix socket path length

The gRPC control socket is an `AF_UNIX` path, limited to ~108 bytes
(`SUN_LEN`). A deep working directory will overflow it and both the mock's
bind and the proxy's connect fail with `path must be shorter than SUN_LEN`.
Keep the socket path short — `verify-rust-proxy.sh` defaults it under
`$XDG_RUNTIME_DIR` (or `/tmp`), not under the (possibly deep) workdir, and
errors early if an override is too long.

## Verified result (2026-07-06)

Driving `remote-viewer` through the proxy to a booted qemu SPICE server, the
proxy's metrics showed `authorized_total 4` (main/display/inputs/cursor
channels), `bytes_relayed_total{server_to_client} ~345 KB` of display data
and `{client_to_server}` input traffic, with the mock logging
`AuthorizeConnection` per channel and `DeregisterChannel` on teardown —
confirming the full client → proxy → hypervisor path.
