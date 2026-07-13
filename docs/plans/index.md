# Plans index

This page summarises every planning document in chronological order.
Master plans decompose work into numbered phases, each with its own
detailed plan file. Standalone plans track issues, follow-ups, or
design decisions that do not require phased execution.

New plans should follow the structure in `PLAN-TEMPLATE.md` at the
repo root. For pre-push audits of our own work see
`PUSH-TEMPLATE.md`.

## Master plans

| Date | Plan | Intent | Status | Phases |
|------|------|--------|--------|--------|
| 2026-06-02 | [Automated SPICE test harness](PLAN-test-harness.md) | End-to-end SPICE test harness driving Uncalibrated Sextant via Ryll's control socket, with assertions against the visual digest and serial drain; replaces the OpenStack-dependent integration tests with a direct qemu/KVM lane | Not started | (phase plans pending) |
| 2026-07-04 | [Rust SPICE proxy (kerbside-proxy)](PLAN-rust-proxy.md) | Replace the Python SPICE proxy with a Rust kerbside-proxy that talks tonic/gRPC over a UDS to the Python daemon, reuses ryll's shakenfist-spice-protocol crate, enforces L0+L1 firewall policy from day one, and ships inside the kerbside pip install via a maturin bin wheel | Complete | [phase 1](PLAN-rust-proxy-phase-01-server-primitives.md) (done), [phase 2](PLAN-rust-proxy-phase-02-grpc-contract.md) (done), [phase 3](PLAN-rust-proxy-phase-03-proxy-skeleton.md) (done), [phase 4](PLAN-rust-proxy-phase-04-firewall.md) (done), [phase 5](PLAN-rust-proxy-phase-05-daemon-integration.md) (done), [phase 6](PLAN-rust-proxy-phase-06-packaging.md) (done), [phase 7](PLAN-rust-proxy-phase-07-ci.md) (done), [phase 8](PLAN-rust-proxy-phase-08-cutover.md) (done) |

## Standalone plans

| Date | Plan | Intent | Status |
|------|------|--------|--------|
