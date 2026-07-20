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
| 2026-06-02 | [Automated SPICE test harness](PLAN-test-harness.md) | End-to-end SPICE test harness driving Uncalibrated Sextant via Ryll's control socket, with assertions against the visual digest and serial drain; replaces the OpenStack-dependent integration tests with a direct qemu/KVM lane | Complete | [phase 1](PLAN-test-harness-phase-01-digest-crate.md) (done), [phase 2](PLAN-test-harness-phase-02-static-hypervisor.md) (done), [phase 3](PLAN-test-harness-phase-03-control-socket.md) (done), [phase 4](PLAN-test-harness-phase-04-port-latency.md) (done), [phase 5](PLAN-test-harness-phase-05-direct-qemu-ci.md) (done), [phase 6](PLAN-test-harness-phase-06-digest-decoding.md) (done), [phase 7](PLAN-test-harness-phase-07-scenario-test.md) (done), [phase 8](PLAN-test-harness-phase-08-openstack-disposition.md) (done) |
| 2026-07-04 | [Rust SPICE proxy (kerbside-proxy)](PLAN-rust-proxy.md) | Replace the Python SPICE proxy with a Rust kerbside-proxy that talks tonic/gRPC over a UDS to the Python daemon, reuses ryll's shakenfist-spice-protocol crate, enforces L0+L1 firewall policy from day one, and ships inside the kerbside pip install via a maturin bin wheel | Complete | [phase 1](PLAN-rust-proxy-phase-01-server-primitives.md) (done), [phase 2](PLAN-rust-proxy-phase-02-grpc-contract.md) (done), [phase 3](PLAN-rust-proxy-phase-03-proxy-skeleton.md) (done), [phase 4](PLAN-rust-proxy-phase-04-firewall.md) (done), [phase 5](PLAN-rust-proxy-phase-05-daemon-integration.md) (done), [phase 6](PLAN-rust-proxy-phase-06-packaging.md) (done), [phase 7](PLAN-rust-proxy-phase-07-ci.md) (done), [phase 8](PLAN-rust-proxy-phase-08-cutover.md) (done) |
| 2026-07-17 | [Backend host_subject enforcement](PLAN-host-subject.md) | Restore hypervisor certificate subject pinning on the proxy's backend TLS leg, lost in the Rust proxy cutover: enforce spice-common host-subject matching semantics in ryll's shakenfist-spice-protocol verifier, adopt it in kerbside, and prove both accept and refuse paths in the direct-qemu CI lane | Complete | [phase 1](PLAN-host-subject-phase-01-ryll-verifier.md) (done, ryll PR #166), [phase 2](PLAN-host-subject-phase-02-kerbside-adoption.md) (done, kerbside PR #114) |
| 2026-07-19 | [Shaken Fist VDI console tokens](PLAN-kerbside-vdi-tokens.md) | Cross-repo plan (master in shakenfist's docs/plans/): per-instance console authorisation via short-lived Ed25519-signed tokens minted by Shaken Fist and validated offline by kerbside; kerbside side adds an `/sf-console.vv` exchange endpoint mirroring the Nova flow, a jti replay table, cluster-wide scraping, and host_subject for SF consoles | In progress | [phase 5](PLAN-kerbside-vdi-tokens-phase-05-exchange.md) (done), [phase 6](PLAN-kerbside-vdi-tokens-phase-06-scrape.md) (in progress); 7-8 tracked here as they start (0-4 done in shakenfist / ryll / client-python) |

## Standalone plans

| Date | Plan | Intent | Status |
|------|------|--------|--------|
| 2026-07-16 | [Consistency audit deferred work](PLAN-consistency-audit.md) | Track items from the PROJECT-CONSISTENCY-AUDITS.md review that need manual GitHub UI action: security settings and repository merge settings | In progress |
