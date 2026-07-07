# Validating the Rust proxy firewall (phase 4, step 4f)

This extends the standalone harness in [`VERIFY-RUST-PROXY.md`](VERIFY-RUST-PROXY.md)
to validate the phase-4 L0/L1 firewall against **real** SPICE clients without
risking a broken session, and to drive the connection-denial path end to end.

The proxy takes its firewall policy **only** from the `AuthorizeConnection`
gRPC reply (`FirewallPolicy`, Design decision 1 of
`docs/plans/PLAN-rust-proxy-phase-04-firewall.md`). So the validation is done
by having the mock control-plane deliver a **warn-only** policy and then
scraping Prometheus: a full legitimate session that trips **zero** firewall
verdicts proves the compiled allowlist and size caps cover real traffic. No
Rust flags are involved — the mock is the policy source.

## The two knobs the mock now delivers

`mock-grpc-server.py` attaches a `FirewallPolicy` to every SUCCESS reply and
can deny connections:

| Flag / env | Effect |
|------------|--------|
| `--firewall-mode {enforce,warn}` / `MOCK_GRPC_FIREWALL_MODE` | `FirewallPolicy.mode`. `warn` = WARN_ONLY: blocking verdicts are downgraded to forward+log, counted as `action=observed`. The session is never actually blocked — this is the safe capture mode. Default `enforce`. |
| `--permitted-channels CSV` / `MOCK_GRPC_PERMITTED_CHANNELS` | Channel NAMES (`main,display,inputs,cursor,playback,record,tunnel,smartcard,usbredir,port,webdav`) mapped to `ChannelType` discriminants 1..11, exactly like `kerbside/rpc/servicer.py`. Empty (default) = permit all channels. |
| `--deny-token TOKEN` (repeatable) / `MOCK_GRPC_DENY_TOKEN` (CSV) | Return `Denied(reason=...)` instead of a `Target` when the decrypted plaintext token matches — drives the proxy's `send_auth_result(PermissionDenied)` path. Denied replies carry NO `firewall_policy`. |
| `--deny-all` / `MOCK_GRPC_DENY_ALL` | Deny every `AuthorizeConnection` unconditionally. |

`verify-rust-proxy.sh` threads these in as env vars: `FIREWALL_MODE`,
`PERMITTED_CHANNELS`, `DENY_TOKEN`, `DENY_ALL`. (`start-rust-proxy.sh` is
unchanged — it launches the proxy binary, which has no firewall CLI surface;
policy arrives over gRPC.)

## Running a warn-only capture session

Bring the path up with the mock delivering WARN_ONLY, connect a real client,
then assert the session was clean:

```sh
# 1. Bring up qemu + mock (warn-only) + proxy, write console.vv.
FIREWALL_MODE=warn tools/direct-qemu/verify-rust-proxy.sh up

# 2. Connect a real SPICE client through the proxy and drive a full session
#    (log in, move the mouse, type, resize — exercise every channel):
remote-viewer /tmp/kerbside-rust-proxy-verify/console.vv
#    ...or virt-viewer, or ryll headless (see VERIFY-RUST-PROXY.md).

# 3. Assert the legitimate session tripped ZERO firewall verdicts.
tools/direct-qemu/verify-rust-proxy.sh assert-firewall     # FIREWALL_EXPECT=clean (default)

# 4. Tear down.
tools/direct-qemu/verify-rust-proxy.sh down
```

Repeat step 2 for each supported client: **virt-viewer**, **remote-viewer**,
and **ryll headless**.

### What a clean result looks like

`assert-firewall` (with the default `FIREWALL_EXPECT=clean`) waits for a real
session — `kerbside_proxy_authorized_total >= 1` and
`kerbside_proxy_bytes_relayed_total > 0` in both directions — then reports the
`kerbside_proxy_firewall_verdicts_total` series split into `enforced` vs
`observed` and **passes only if both sums are 0**:

```
[verify-rust-proxy] authorized=4 denied=0 bytes{c2s}=... bytes{s2c}=... verdicts{enforced}=0 verdicts{observed}=0
[verify-rust-proxy] verdict series:
[verify-rust-proxy]   (no firewall_verdicts_total series present -- zero verdicts)
[verify-rust-proxy] PASS: full session relayed with ZERO firewall verdicts (allowlist + caps cover all observed traffic)
```

Because the run is WARN_ONLY, any verdict shows up as `action=observed`: it
tells you exactly what `Enforce` *would* have blocked on legitimate traffic —
a false positive. The fix is to widen the compiled allowlist table or the size
cap for the offending `(channel, direction, rule)` printed in the failure, per
Design decision 3 — never to weaken the verdict. Feed observed peak message
sizes back into the 4c caps.

## Running the deny-mode check

To drive the previously-untested `PermissionDenied` path, deny the token in
`console.vv` (its `password=` is the plaintext token after the proxy decrypts
it) or deny everything:

```sh
# Deny everything (simplest):
DENY_ALL=1 tools/direct-qemu/verify-rust-proxy.sh up
remote-viewer /tmp/kerbside-rust-proxy-verify/console.vv   # should be refused
FIREWALL_EXPECT=deny tools/direct-qemu/verify-rust-proxy.sh assert-firewall
tools/direct-qemu/verify-rust-proxy.sh down

# Or deny one specific token:
DENY_TOKEN=rust-proxy-verify-any-token-works \
    tools/direct-qemu/verify-rust-proxy.sh up
```

With `FIREWALL_EXPECT=deny`, the assertion requires
`kerbside_proxy_denied_total >= 1` (it does **not** require bytes relayed,
since the session is legitimately refused before relay). This is the
expectation flag that distinguishes a deny-mode run from a clean capture run.

## Caveat: unix socket path length (SUN_LEN)

Unchanged from `VERIFY-RUST-PROXY.md`: the gRPC control socket is an `AF_UNIX`
path limited to ~108 bytes. `verify-rust-proxy.sh` defaults it to a short path
under `$XDG_RUNTIME_DIR` (or `/tmp`), not under the (possibly deep) workdir,
and errors early if a `GRPC_SOCKET` override is too long.

## Live capture RESULTS

Run 2026-07-07, proxy built at ryll pin `1c6f19f` (the completed
main/display message-type tables), release binary, against the
`uncalibrated-sextant.qcow2` guest under qemu (TCG, no KVM in this env).

- **Date / proxy build:** 2026-07-07; `rust/kerbside-proxy` release, ryll
  rev `1c6f19f`.
- **Client versions:** remote-viewer (spice-gtk) — the primary client
  driven. virt-viewer was not run separately: it links the same
  spice-gtk client engine as remote-viewer, so the client→server message
  grammar it emits is the same. **ryll headless was NOT run in this
  pass** — it is a distinct client implementation and remains a
  worthwhile follow-up capture.
- **Channels carried:** 4 — main, display, inputs, cursor. record,
  playback, smartcard, usbredir/port/webdav were NOT opened by this
  client+guest. This confirms the `ChannelUnmodeled` (observe-only)
  handling of record/smartcard is safe for this workload, and **no
  4b-ryll table work is needed** for them right now.
- **Warn-only verdict counts** (proxy run with `FIREWALL_MODE=warn`;
  expect all `observed=0`):
  - remote-viewer: **PASS** — 4 channels authorized, ~1.17 MB relayed
    (`bytes{s2c}=1,174,716`, `bytes{c2s}=1,468`), and
    `firewall_verdicts_total` had **zero series** (enforced=0,
    observed=0). Every framed message across the four channels was
    Allowed and within its size cap — no false positives.
  - virt-viewer: not run (same spice-gtk engine as remote-viewer).
  - ryll headless: not run (follow-up).
- **Observed max message sizes fed back into 4c caps:** no cap was
  approached — the tight 4 KiB inputs/cursor-client cap and the generous
  16 MiB elsewhere held with zero `size_cap` verdicts, so no cap was
  retuned. (Display server frames stayed well under the generous cap.)
- **Deny-mode check:** `DENY_ALL=1`, `FIREWALL_EXPECT=deny` → **PASS**:
  `authorized=0`, `denied=1`, no bytes relayed. The proxy sent
  `PermissionDenied` and refused the connection before relay, exercising
  the client-denial path end to end.
- **Caps / allowlist tuned as a result:** none needed.
- **Notes / anomalies:** the `assert-firewall` helper had a bug — under
  `set -o pipefail`, `_verdict_sum` aborted the script when the
  `firewall_verdicts_total` series was entirely absent (exactly the
  clean, zero-verdict case); fixed so a no-match yields 0. The
  `need_secured` backend retry orchestration was NOT exercised here
  (would need a TLS-requiring backend); it remains covered only by the
  `is_need_secured` unit tests, tracked as a follow-up.
