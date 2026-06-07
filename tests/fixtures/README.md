# Test fixtures

Binary fixtures consumed by the kerbside test harness.

**uncalibrated-sextant.qcow2** — the Uncalibrated Sextant UEFI guest image, built from
https://github.com/shakenfist/uncalibrated-sextant by running `make release` in that repo
and copying the result here. Refresh via `tools/direct-qemu/rebuild-sextant-qcow2.sh`.
Used by the direct-qemu CI lane (`.github/workflows/direct-qemu-functional.yml`).
Last refreshed: 2026-06-07.

See docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md for the broader rationale.
