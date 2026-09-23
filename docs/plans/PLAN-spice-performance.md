# SPICE session performance, in Kerbside and upstream

## Prompt

Before acting on this plan, read the kerbside proxy relay
(`rust/kerbside-proxy/src/relay.rs`, `listen.rs`,
`backend.rs`), the latency loadtest (`loadtests/latency/`)
and the direct-qemu harness (`docs/direct-qemu-harness.md`).
The upstream claims below cite the reference clones under
`/srv/src-reference/` (qemu, spice, libvirt, the kernel) at
the commits named in the Situation section. Re-check a
citation before you build on it: these trees move, and a
line number is only a pointer. Ground every claim in the
code rather than in this document, and flag uncertainty
rather than guessing.

## Situation

On 2026-09-23 we asked: if we could change anything in qemu,
spice-server, libvirt or the Linux kernel, what would most
improve the performance or quality of SPICE sessions for
Kerbside and Ryll? Four research agents surveyed the display
pipeline, the transport and authentication model, the kernel,
and the pain points already recorded in Kerbside, Ryll and
kerbside-patches. The sources read were qemu 30e8a06b64
(2026-06-29), spice 91d42c4d (2026-06-30) and linux
c537e12daeec. The management session spot-checked the main
claims against source. What follows is the result, ranked.

### The findings that shape this plan

1. **Kerbside hides congestion from spice-server.** The proxy
   sets only `TCP_NODELAY` and keepalive
   (`rust/kerbside-proxy/src/listen.rs:100,169`). The relay
   pump reads, forwards each message with `write_all` and
   flushes (`relay.rs:211-352`). Backpressure therefore reaches
   spice-server only after two things fill: the client leg's
   autotuned send buffer and the backend leg's receive buffer.
   Both can reach megabytes, which is seconds of stale frames
   at WAN rates. spice-server's own defences, the channel
   "blocked" state and pipe frame dropping
   (`red-channel-client.cpp:665,685`, `video-stream.cpp:354`),
   rely on its socket stalling, and the proxy prevents that.
   The kernel already has the fix, `TCP_NOTSENT_LOWAT` plus
   capped socket buffers, through `socket2`, which we already
   depend on. No upstream change is needed.
2. **qemu's non-GL SPICE display path defeats spice-server's
   video detection.** This path serves virtio-gpu, std-vga and
   qxl in VGA mode.
   - `ui/spice-display.c:375-391` unions all damage into a
     single bounding box.
   - `qemu_spice_create_update` (`:194-258`) diffs that box
     against a mirror in 32-pixel columns and emits one
     `DRAW_COPY` per column run.
   - Each update is copied twice.
   - Updates wait for a fixed 30 ms timer
     (`include/ui/console.h:39`).
   - spice-server starts a stream only after 20 consecutive
     same-geometry copies of at least 96x96
     (`server/video-stream.h:32-38`). Column-shaped drawables
     rarely qualify, so video on virtio-gpu falls back to
     bitmaps. That explains Ryll's unmeasured OPEN-QUESTIONS Q3
     and undercuts "move off QXL" as a standalone answer. The
     move is still right, because QXL's command ring exhaustion
     and resolution cliff are structural, but it only pays off
     once this path is fixed.
3. **spice-server's authentication model is the main
   constraint on brokering.**
   - There is one password per VM (`reds.cpp:3931-3961`).
   - It is re-checked with `strcmp` against one global expiry
     on every channel link (`reds.cpp:2087-2110`).
   - It is carried in RSA-1024 OAEP with SHA-1 and limited to
     60 bytes.

   Minting a second ticket revokes the first viewer.
   `PLAN-proxmox-source.md` meets this directly, and it puts a
   ticket lifetime floor under every late-opened channel. Fixing
   it upstream means spice-server, qemu QMP, libvirt and every
   platform adopting the change: years.
4. **qemu already offers a supported out-of-process display
   interface, and there is precedent for a Rust server on it.**
   - `-display dbus` (`ui/dbus-display1.xml`) exports:
     - scanout, and per-rectangle `Update`s;
     - shared-memory `ScanoutMap`/`UpdateMap`, and DMABUF;
     - cursor, keyboard, mouse and multitouch;
     - clipboard;
     - audio in and out;
     - chardevs, which covers vdagent and usbredir.
   - libvirt supports `<graphics type='dbus'/>` (since 8.4).
     Since 11.1 it launches an external Rust `qemu-rdp` helper
     against it (`docs/formatdomain.rst:6898`).
   - A SPICE server built the same way, as a per-VM helper
     reusing Ryll's `shakenfist-spice-protocol` server
     primitives, would sidestep findings 2 and 3 together:
     - it takes damage without going through
       `spice-display.c`;
     - it chooses its own codecs, including hardware H.264
       from the dmabuf;
     - it defines its own ticketing.
   - qemu's SPICE modules (`ui/meson.build:176-188`) are not an
     alternative plug point. `util/module.c:176-186` refuses
     modules from any other build.
   - A drop-in `libspice-server.so` is possible, since it is a
     stable ABI of about 99 symbols. It would still receive
     drawables that qemu has already mangled in finding 2.

### The wider ranked list

These are not all phases of this plan; see Execution and
Future work for what is scheduled.

| # | Change | Where | Upstream odds |
|---|--------|-------|---------------|
| 0 | Proxy socket backpressure | Kerbside | Ours |
| 1 | Rect-list damage, damage-driven pacing, no column slicing, one copy | qemu `ui/spice-display.c` | Good |
| 2 | Per-session, scoped, one-time tickets; secondary channels authenticate by `connection_id` | spice-server, qemu, libvirt | Medium |
| 3 | Lossless refinement when idle, and real damage for remote `gl=on` | spice-server, qemu | Plausible |
| 4 | Vendor-neutral hardware encode, enable the dormant H.265 path, 60 fps ceilings, faster bitrate ramp | spice-server `gstreamer-encoder.c` | Very plausible |
| 5 | Atomic `FB_DAMAGE_CLIPS` in the guest qxl driver | Linux `drivers/gpu/drm/qxl` | Slow (dormant driver) |
| 6 | Link-quality hint from the proxy; client-initiated RTT ping | spice-server, spice-protocol | Medium-high |
| 7 | Disconnect reasons, ticket id and per-channel stats in QMP events | spice-server, qemu, libvirt | High |
| 8 | Token auth inside TLS replacing RSA-1024/SHA-1 | spice-protocol, spice-server | Medium-high |
| 9 | `NUM_TRACE_ITEMS` 8 to 64; GLZ invalidations in the zlib fallback | spice-server | High |

Ruled out: kTLS, splice, `MSG_ZEROCOPY` and io_uring
zero-copy in the proxy. Kerbside must parse plaintext and
re-encrypt each leg, and SPICE runs at tens of Mbit/s, so
copies are not the bottleneck. A virtio-gpu "this region is
video" hint was also ruled out: it needs a virtio spec change
plus compositor cooperation, and precise damage gets most of
the benefit.

Things that already work and we do not use:
- remote `gl=on` with hardware H.264 (spice-server 0.15.3 or
  later);
- `virDomainOpenGraphicsFD` with skipauth, for a co-located
  proxy. It is blocked only because `reds_security_check`
  treats AF_UNIX as insecure (`reds.cpp:2193`);
- TLS session resumption on the backend leg.

## Mission

Make SPICE sessions through Kerbside measurably faster and
better looking, in three horizons:

- **now**, in our own code (the proxy);
- **soon**, through small upstream patches to the in-qemu
  SPICE path that existing Nova and oVirt deployments will run
  for years;
- **later**, by testing whether a Rust SPICE server on qemu's
  D-Bus display is a better foundation than spice-server.

Every change is measured before and after; Kerbside has no
recorded latency figures today (the latency loadtest only
uploads CI artifacts), so producing a baseline is part of the
first phase.

## Open questions

1. **How do we measure a WAN link?** Phase 1's problem does not
   exist on loopback. The measurement needs a shaped client leg
   (`tc` netem plus tbf on a veth pair or network namespace),
   which needs `CAP_NET_ADMIN`. The first phase decides whether
   that stays a local procedure or can run in the direct-qemu
   lane.
2. **Where do upstream patch series and a helper binary live?**
   Out-of-tree qemu work needs a home that is not
   kerbside-patches (which targets OpenStack). The son-of-SPICE
   spike likely wants its own repository if it survives. This
   is decided when phase 2 or 3 is planned.
3. **Does Kerbside's role change if phase 3 succeeds?** A helper
   that owns ticketing and speaks SPICE could enforce the
   firewall itself, or Kerbside could stay in front of it.
   Answering that is an output of phase 3, not an input.

## Execution

| Phase | Plan | Status | Merged |
|-------|------|--------|--------|
| 1. Proxy backpressure and a WAN baseline | [PLAN-spice-performance-phase-01-proxy-backpressure.md](PLAN-spice-performance-phase-01-proxy-backpressure.md) | In progress | |
| 2. qemu damage path: prototype, measure, send upstream | | In progress | |
| 3. Son of SPICE: D-Bus display feasibility spike | | Not started | |
| 4. Small spice-server patches (items 4 and 9) | | Not started | |
| 5. Push audit | | Not started | |

**Phase 1** sets `TCP_NOTSENT_LOWAT` on the client leg and caps
the backend leg's receive buffer, with the values made
configurable. It measures keypress-to-draw latency with the
existing loadtest over a shaped link, before and after. That
produces Kerbside's first recorded latency figures. The
per-socket congestion control choice (BBR) is measured, not
assumed.

**Phase 2** started on 2026-09-23 as an out-of-tree prototype.
It is a patch series against qemu `ui/spice-display.c`,
measured with Ryll in headless mode against a virtio-gpu guest
on stream creation, `DRAW_COPY` shapes and display-channel
bytes. The phase plan is written once the prototype has
reported; it covers where the series lives and the qemu-devel
submission. Its `Merged` cell records `qemu <sha>`, and the
push audit cites the upstream review rather than re-running
it.

**Phase 3** is a time-boxed spike, with three steps:
1. confirm that D-Bus `Update` rectangles for virtio-gpu
   arrive promptly and precisely, which is not yet traced
   through every device's refresh path;
2. build a minimal helper (main, display, inputs, cursor,
   LZ4, one client) on Ryll's protocol crate;
3. compare it against in-qemu SPICE on the phase 2 workload.

Its output is a go or no-go recommendation, with a proposal
for a separate master plan if the answer is go.

Design inputs for phase 3, from the low-latency streaming
stacks: NVIDIA GameStream and its open reimplementation
Sunshine/Moonlight, Amazon DCV, PCoIP and Parsec. The spike
does not build these, but it must not make choices that rule
them out:

- **The frame stays on the GPU.** Capture scanout as a dmabuf
  (D-Bus `ScanoutDMABUF`, or udmabuf for a 2D guest), convert
  RGB to YUV on the GPU, and encode in hardware (NVENC, VA-API,
  V4L2 m2m). There is no CPU readback.
- **Encoder tuned for latency, not efficiency.** That means:
  - no B-frames;
  - an infinite GOP with intra-refresh;
  - a VBV of about one frame;
  - slice output, so the first slices are sent before the frame
    finishes encoding;
  - HEVC or AV1 4:4:4 (or lossless refinement when idle) so
    that text stays sharp.
- **Loss recovery without keyframes.** The client acknowledges
  frames, and on loss the encoder invalidates reference frames
  (NVENC `nvEncInvalidateRefFrames`) and falls back to the last
  acknowledged one.
- **A UDP transport.** QUIC or DTLS-SRTP, with FEC and
  congestion control driven by continuous RTT and loss feedback.
  This avoids TCP head-of-line blocking. It is the biggest
  departure from SPICE, and it means Kerbside would need a
  QUIC-terminating relay path next to its TCP one. Kerbside
  still fronts the helper either way: hypervisor ports are
  never exposed to clients.
- **Frame pacing.** Frames are paced to the client's display
  rather than to a server timer. The cursor stays client-side.
  Input travels on its own low-latency path.

**Phase 4** takes the upstream items that are cheap and
server-internal: vendor-neutral hardware encoder probing,
enabling H.265, 60 fps ceilings, a larger stream trace ring
and GLZ invalidations. It is scheduled after phase 3, because
a go there would reduce the value of patching spice-server.

<!-- shared-block: plan-push-audit-phase v3 -->
Push audit phase (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-push-audit-phase.md`):

- Every master plan ends with a phase that runs the repository's
  `PUSH-AUDIT.md` over the whole plan's work. It is the last row of
  the Execution table and it is not optional. The rule binds every
  plan that carries the phase, which is decidable from the plan file
  alone: a plan that is already `Complete`, `Abandoned` or
  `Superseded` and does not carry the phase is not reopened to
  acquire one, and a plan that has the phase runs it even if it
  reaches `Complete` before the phase does.
- That phase audits the accumulated diff of every phase in the plan
  against the default branch, not the diff of the last phase alone.
  Auditing one phase at a time would miss what the phases did to
  each other -- the duplicated helper that only exists once phases
  three and six have both landed, the doc page that phase two made
  wrong and phase five never revisited.
- Once the plan's phases have merged, a diff against the default
  branch is empty and would read as a clean audit. The range is not
  reliably derivable after the fact either: unrelated work lands on
  the default branch between phases, so anything anchored on "since
  the plan file appeared" is far too wide. It has to be recorded. As
  each phase lands, what put it on the default branch goes into the
  plan: the merge commit of its pull request, whose diff against its
  first parent is the whole of what landed, or -- where the phase
  landed directly -- every commit of the phase, or its `first..last`
  range. A single commit is only ever enough when it is a merge
  commit.
- Where the Execution phases are a table, that record is a `Merged`
  column, added last so that a row which omits it still reaches
  `Status`; where they are prose sections it is a `Merged:` line in
  the phase's own section. The `Status` column keeps its single
  vocabulary term and nothing else (see `plan-status-vocabulary`).
  A phase that landed in another repository records `<repo> <sha>
  (#pr)` and is audited against that repository's default branch, as
  part of the pull request that lands it; the plan's own push-audit
  phase cites that audit rather than re-running it.
- Phases that landed before the plan started recording them are
  reconstructed rather than left blank. Recover what you can from
  `gh pr list --state merged` and `git rev-list --first-parent`, and
  say in the plan that the range was reconstructed. Do not trust a
  path-filtered `git log` on its own: it lists the commits that
  touched a path without saying which arrived directly and which
  arrived inside a pull request, and recording a commit that came in
  under a merge audits one commit of that pull request rather than
  the pull request. A reconstructed record may be a summary table in
  the audit phase's own section rather than a column or a line in
  the Execution table, which keeps retrospective archaeology out of
  a table that tracks live status. Where a phase accreted over
  months of unrelated commits and no range is recoverable, say that
  instead and name the paths the audit read -- an audit that says
  what it could not scope is a result; one that silently audits
  nothing is not.
- Findings land as their own pull request against the default
  branch, and the plan is not complete until they are resolved or
  explicitly declined in writing. A finding that is declined says
  why, in the plan, where the next reader will find it.
- Where the audit finds nothing, record that in the plan in one
  sentence. It is a real result, and a run of them is the evidence
  for making the phase conditional rather than mandatory.
- A repository with no `PUSH-AUDIT.md` still carries the phase, and
  the phase says that the runbook does not exist yet and what was
  done instead. Silently omitting it is what let the audit go
  untriggered for as long as it did.
<!-- shared-block-end -->

## Agent guidance

Phases follow `PLAN-TEMPLATE.md`'s sub-agent execution model:
implementation by sub-agents, review and commits in the
management session. Phases 2 and 3 involve protocol and
upstream-codebase judgement and are planned at high effort;
phase 1 and phase 4 at medium. Rust builds run in Docker, per
the proxy's Makefile, never with a native toolchain on the
host.

## Future work

These upstream items from the ranked list are deliberately not
scheduled. Items 2, 6, 7 and 8 all depend on phase 3's
verdict: if a Rust helper owns the SPICE server, we define
ticketing, link hints and observability ourselves and never
need spice-server to change. If phase 3 is a no-go, they
become the next plan:

- per-session, scoped, one-time tickets (item 2);
- a proxy link-quality hint and a client RTT ping (item 6);
- richer QMP session events (item 7);
- token authentication inside TLS (item 8). This would also
  unpin Ryll from SHA-1-era RustCrypto crates (ryll #93).

Other deferred items:

- lossless refinement for remote `gl=on` (item 3);
- `FB_DAMAGE_CLIPS` for the guest qxl driver (item 5). It is
  only worth doing if QXL guests stay common;
- treating AF_UNIX as secure in `reds_security_check`, which
  would unlock fd-passed backend attachment for a per-hypervisor
  Kerbside;
- TLS session resumption on the proxy's backend leg, which
  needs no upstream change.

## Bugs fixed during this work

None yet.

## Back brief

Before executing any step of this plan, back brief the
operator on your understanding of the plan and how the work
you intend to do aligns with it.
