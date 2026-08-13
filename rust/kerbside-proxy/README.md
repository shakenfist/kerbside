# kerbside-proxy

The Kerbside SPICE proxy: an inspection-first TLS relay between SPICE
clients and hypervisors, authorised via the Kerbside gRPC control
service. It is the Rust replacement for the original Python SPICE proxy
in [`kerbside`](https://github.com/shakenfist/kerbside).

This package ships a single compiled binary, `kerbside-proxy`. It is
published to PyPI as a separate package from the pure-Python `kerbside`
package and is an exact-version dependency of it, so `pip install
kerbside` installs a matching proxy and puts `kerbside-proxy` on `PATH`.
The `kerbside` daemon supervises the binary as a child process; you do
not normally run `kerbside-proxy` directly.

## Building from source

The crate lives at `rust/kerbside-proxy/` in the `kerbside` repository.
Its `build.rs` compiles the gRPC contract from
`../../kerbside/rpc/kerbside.proto`, so a build must run with the
repository root available (see the crate `Makefile`, which wraps the
build in Docker and mounts the repo root). To build a wheel:

```
pip install maturin
maturin build --release   # run from rust/kerbside-proxy/
```

See `RELEASE-SETUP.md` for the packaging and release design.

## Licence

Apache-2.0. See the `LICENSE` file at the repository root.
