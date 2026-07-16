# Test fixtures

Binary fixtures consumed by the kerbside test harness.

**uncalibrated-sextant.qcow2** — the Uncalibrated Sextant UEFI guest image, built from
https://github.com/shakenfist/uncalibrated-sextant by running `make release` in that repo
and copying the result here. Refresh via `tools/direct-qemu/rebuild-sextant-qcow2.sh`.
Used by the direct-qemu CI lane's scenario test
(`.github/workflows/direct-qemu-functional.yml`).
Last refreshed: 2026-06-07.

**uefi-latency-guest.qcow2** — the purpose-built keypress-to-screen latency target,
a UEFI guest that repaints its SPICE display on every keypress (and never advances
through irreversible states), so the latency loadtest collects a clean sample set.
Committed here (rather than the historical runtime download) to keep the direct-qemu
lane hermetic. Refresh by re-downloading
https://images.shakenfist.com/testimages/uefi-latency-guest.qcow2.
Used by the direct-qemu CI lane's non-gating latency loadtest
(`tools/direct-qemu/run-loadtest.sh`).
Last refreshed: 2026-07-16.

See docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md for the broader rationale.
