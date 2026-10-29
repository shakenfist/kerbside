# Phase 5: spice-server patches, measured

Master plan: [PLAN-spice-performance.md](PLAN-spice-performance.md).
Planning effort: high. The master plan rates phase 5 medium, as
small server-internal patches. The survey changed that. One of
the two items it names is withdrawn, the other splits four ways,
and the plan's main obstacle to recommending
`streaming-video=all` (a spice-server crash) turns out to belong
here. Deciding which patches are worth carrying needs protocol
judgement.

The master plan's phase 5 section is the brief this plan refines.
What follows grounds it in spice-server master as of 2026-10-30
(adeb620a04) and changes the scope where the code disagreed.

## Scope

In:
- finding out why phase 4's `streaming-video=all` runs sent MJPEG
  when every earlier page reports H.264. The answer decides what
  every later measurement here is a measurement of;
- reproducing spice-server 0.15.2's connect crash, on 0.15.2,
  0.16.0 and master, and then either patching it or naming the
  commit that fixed it;
- three small spice-server patches, each kept only if the rig
  shows it helps:
  - the stream trace ring raised from 8 entries to 64 (item 9);
  - the stream frame-rate ceiling raised from 30 to 60 (item 4);
  - hardware encoder probing that is not limited to Intel GPUs
    (item 4);
- a series of the patches that earned their place, in
  kerbside-patches under `upstream/spice/`, with
  `disposition: submit`, plus the build script and the results
  tables;
- a write-up in kerbside's `docs/performance/`, and the master
  plan updates.

Out, each with its reason:
- **GLZ invalidations in the zlib fallback** (item 9's second
  half). This is not a server defect (survey, finding 3). It is
  withdrawn.
- **Enabling H.265** (item 4). The rig cannot measure it: Ryll
  has no H.265 decoder (it only names codec 5 in
  `shakenfist-spice-renderer/src/control/protocol.rs:482`), and
  remote-viewer reports no timings. It goes to Future work.
- **A faster bitrate ramp** (item 4). The research named it
  without a defect or a measurement behind it. The 60 fps
  measurement will show whether rate control is slow to react. If
  it is, that is a finding for Future work, not a patch here.
- **Submitting anything upstream.** Sending patches to
  spice-server is Mikal's act, as it is for the Linux and Open
  vSwitch series. This phase leaves a series ready to send.
- **The operator recommendation for `streaming-video`.** It
  depends on this phase's crash answer and on which spice-server
  versions distributions ship. It stays in Future work, and its
  facts get recorded here.
- **Kerbside product code.** If step 1 finds that the proxy drops
  the client's codec preference, that is a kerbside bug. It gets
  an issue and its own pull request, not a fix inside this phase.

## What the survey found

spice-server was cloned at master adeb620a04 (2026-10-29). The
host runs Debian 13, with libspice-server1 0.15.2, qemu 10.0.13
and GStreamer 1.26. The plan's figures were checked against
these.

1. **spice-server takes AI-assisted patches, unlike qemu.** 55
   commits since 2026-02-09 carry `Co-Authored-By: Claude`.
   Marc-André Lureau, the maintainer, wrote 54 of them. One is
   from an outside contributor (Mark Junker, 9d6be696). There is
   no written policy in the tree either way. The barrier that
   stopped the qemu series (master plan, phase 2) does not apply.
   A series here is `submit`, not `carry`.
2. **Master is very active.** About 40 commits since 2026-10-02,
   mostly hardening by the maintainer:
   - use-after-frees in `dcc.cpp` (6774c046);
   - leaks in `dcc-send.cpp`;
   - ticket handling in `reds.cpp`;
   - a gstreamer dmabuf stride fix (4ff6e95f).

   None of them names the connect crash. `video-stream.cpp`
   changed only in c4a2f27e (a GL stream's `dest_area`), and
   `VideoStreamClipItem` is untouched since 0.15.2. Whether the
   crash survives on master is therefore open, and step 2's first
   job. 0.16.0 was tagged on 2025-05-05. Debian 13 still ships
   0.15.2, from 2022-11-09.
3. **The GLZ half of item 9 is not a server defect.** It traces
   to Ryll's research note "~30 MiB/s dictionary growth". Ryll
   recorded that as client-side cache growth
   (`docs/troubleshooting.md`, "Display image cache pressure").
   Every GLZ image carries its window-head distance
   (`server/glz-encoder.c:275`), which is how the server tells
   the client which dictionary entries to drop, zlib-wrapped or
   not. Ryll has honoured it since 8b1276d (2026-04-02), before
   the research ran. There is nothing to invalidate. The item is
   corrected at its source in the master plan.
4. **The trace ring is as described, but its effect is
   unmeasured.**
   - `TRACE_ITEMS_SHIFT` is 3, so `NUM_TRACE_ITEMS` is 8
     (`server/display-channel-private.h:25-26`).
   - `video_stream_trace_add_drawable` (`video-stream.cpp:1048`,
     called from `display-channel.cpp:368`) records a streamable
     drawable that leaves the tree without a stream.
   - `video_stream_trace_update` (`video-stream.cpp:627`, ring
     searched at `:655`) lets a new drawable of the same geometry
     take over that frame count, rather than starting again at
     zero.
   - The original evidence was Ryll's QXL out-of-memory flap.
     The case that matters now is stock qemu. It cuts damage into
     up to 19 columns per update (master plan, finding 2), more
     than the ring holds, so each update can evict the columns
     the next update needs. That is a hypothesis. Step 4 tests
     it.
5. **Item 4's four parts hold in master.**
   - **Hardware encoding is Intel-only.** `gstreamer_encoder`
     calls `try_intel_hw_plugins` only when udev finds an Intel
     GPU (`gstreamer-encoder.c:1135-1137`). Yet the plugins it
     probes (`msdk`, `va`, `vaapi`, `:963`) include GStreamer's
     `va`, which is vendor-neutral.
   - **This host can measure it.** It has an AMD Phoenix3 GPU
     with a render node, `mesa-va-drivers`, GStreamer's
     `libgstva.so`, and the user is in the `render` group. A
     vendor-neutral probe is testable here; an Intel one was
     not.
   - **H.265 is dormant.** The codec table names it (`:939`), but
     `gstreamer_encoder_new` rejects it (`:2023-2027`), and
     `get_gst_codec_name` has no case for it.
   - **The frame-rate ceiling is 30.** `MAX_FPS` is 30
     (`video-stream.h:46`). It caps the input-fps estimate
     (`video-stream.cpp:390,407`) and the encoder's framerate
     (`gstreamer-encoder.c:56,859`).
6. **qemu 10.0.13 cannot choose a codec, so the client does.**
   `qemu-system-x86_64 -spice help` lists `streaming-video`, but
   no codec option, and `ui-spice-core.so` never calls
   `spice_server_set_video_codecs`. The server's default order is
   `spice:mjpeg` first, then GStreamer's MJPEG, H.264, VP8 and
   VP9 (`reds.cpp:3527-3531`). That order is reordered only by
   the client's `PREFERRED_VIDEO_CODEC_TYPE` message
   (`dcc.cpp:940-966`).
   - So H.264 in the earlier pages means Ryll's preference
     reached spice-server, and MJPEG in phase 4 means it
     probably did not.
   - Ryll sends that message at link-up
     (`shakenfist-spice-protocol/src/constants.rs:164-166`).
   - The proxy relays it only when the client's caps carry
     `PREF_VIDEO_CODEC_TYPE` (`rust/kerbside-proxy/src/caps.rs:278-283`,
     from fa49784, 2026-09-26).
   - The transcoding pages after fa49784 still report H.264,
     which argues against the proxy. Step 1 settles it.
7. **The patched library can be swapped under Debian's qemu.**
   qemu's spice support is a module, `ui-spice-core.so`, linked
   against `libspice-server.so.1`. A wrapper script that sets
   `LD_LIBRARY_PATH` can be given to `run-matrix.sh` as a
   `DISPLAYS` qemu binary. So the rig needs no new code to
   compare spice-server builds, only display entries.
8. **kerbside-patches is ready for a fourth project.**
   `upstream/README.md` documents the layout (`config.yaml`,
   `series/vN/`, `rig/`, `results/`) and the two dispositions.
   Open vSwitch is the closest model: `submit`, with an
   `Assisted-by:` trailer, and Mikal sending.

Corrected at source in this planning commit:
- in the master plan, the ranked list's item 9, the phase 5
  section and its Execution row, and the Future work items this
  phase now owns (the crash and the codec question);
- the phase 5 entry in `docs/plans/index.md`.

## Decisions

1. **Take the crash and the codec question into this phase.** The
   master plan put both in Future work only because they were
   found after phase 5 was written. The crash is a spice-server
   patch, or a named upstream fix, which is exactly this phase's
   kind of work. The plan already calls it the main obstacle to
   recommending `streaming-video=all`. The codec question decides
   what the other measurements mean: an MJPEG run says nothing
   about hardware H.264. This is the decision most likely to be
   argued with, because it widens a phase the master plan called
   small. The alternative is a phase 5 of three patches measured
   against a codec nobody chose, with the crash left waiting.
2. **Patch against master, and compare against 0.15.2 as well.**
   Patches go upstream against master, so master is the baseline
   for each patch. 0.15.2 is what Debian and its derivatives run,
   so each table also has a 0.15.2 row. That shows how much of
   any gain a deployment gets simply by upgrading.
3. **Build spice-server in a Debian 13 container, and run it on
   the host.** The build needs a dozen `-dev` packages, and the
   host stays clean. The container matches the host's glibc and
   GStreamer, so the library it produces loads in the host's
   qemu and finds the host's GStreamer plugins and VA driver.
   The script lives in kerbside-patches
   (`upstream/spice/rig/build-spice.sh`). It takes a ref and
   optional patches, and runs spice-server's own `meson test`.
   It is C, not Rust, so the Docker-Makefile rule for Rust does
   not apply, but the reason behind it does.
4. **One interleaved matrix for every patch.** The patches are
   measured in one `run-matrix.sh` run, as `DISPLAYS` entries
   interleaved by the rig, not in three runs. Drift on one host
   then spreads evenly across them, as it did in phases 3 and 4.
5. **A patch is kept only if it measures as a help, and never a
   regression.** Phase 1's null result set the precedent: a
   change with no measurable effect is recorded and dropped. A
   patch that helps somewhere and hurts somewhere else is kept
   only if it can be made conditional, and the write-up says how.
   The crash fix is judged by its reproducer instead: no crash in
   20 connects that crashed before.
6. **The crash may not need a patch.** If master does not crash,
   step 2 bisects between v0.15.2 and master to find the fixing
   commit. The result is then a fact for the operator
   recommendation (which spice-server version is needed) and a
   backport request for Debian, not a patch.
7. **Mikal sends the series.** The patches carry
   `Assisted-by: Claude Opus 5.5` and no `Signed-off-by`, as the
   Linux series does. Mikal adds his `Signed-off-by` and opens
   the merge requests on gitlab.freedesktop.org. That is an
   outward act under his name. Finding 1 says the project
   accepts this kind of patch; it does not say this session may
   send one.
8. **H.264 for the encoder measurement is forced by the client.**
   qemu cannot set the codec (finding 6). The vendor-neutral probe
   is therefore measured with Ryll preferring H.264. If step 1
   finds that the preference does not reach spice-server, the
   measurement uses a direct connection (Ryll to qemu, no proxy)
   for that row only, and says so.

## Steps

kerbside-patches work happens in a worktree of that repository on
a branch named `spice-server-series`. Kerbside work happens in
this phase's worktree. Guests run under KVM on this host. No step
touches a live system.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1 | high | opus | kerbside-patches worktree | Build script, plus the codec answer. Commit (kerbside-patches): "Build spice-server for the shaped-link rig." The codec finding goes into step 5's write-up. See brief notes. |
| 2 | high | opus | kerbside-patches worktree | The connect crash: reproduce it, then patch it or bisect to the fix. It stops for review. Commit (kerbside-patches), if a patch: "Fix spice-server's crash on connect with streams." See brief notes. |
| 3 | high | opus | kerbside-patches worktree | The three patches against master, each passing `meson test`. Commit (kerbside-patches): "Draft spice-server's stream and encoder patches." See brief notes. |
| 4 | high | opus | none | One interleaved matrix across the spice-server builds, and the results tables. Commit (kerbside-patches): "Measure the spice-server patches." See brief notes. |
| 5 | high | opus | none | Assemble series v1 from the patches that earned it, open the kerbside-patches pull request, then the kerbside write-up and master plan updates. Commits: (kerbside-patches) "Add a spice-server series."; (kerbside) "Write up the spice-server patches." See brief notes. |

Order: strictly sequential. Every step after the first runs the
rig or builds on the one before, and two rig runs on one host
would perturb each other's timings. Step 2 stops for review,
because its answer (a patch, or a bisected upstream fix) changes
what step 5 assembles.

### Brief notes

**Step 1.** Read this plan's survey first, especially findings 6
and 7.

- **Write `upstream/spice/rig/build-spice.sh` in kerbside-patches.**
  - It takes a spice-server ref and an optional directory of
    patches. It builds in a `debian:trixie` container with
    meson, and runs `meson test`. It leaves
    `libspice-server.so.1` in a named output directory.
  - It also writes a `qemu-<name>.sh` wrapper that execs the
    host's `qemu-system-x86_64` with `LD_LIBRARY_PATH` set to
    that directory.
  - It records the ref's full SHA beside the output.
  - It enables GStreamer, LZ4, Opus and SASL, as Debian's package
    does. Read `debian/rules` from Debian's spice source package
    for the configure flags, rather than guessing them.
- **Prove the swap is neutral.** Build v0.15.2 with the script,
  then run a short `run-matrix.sh` with two `DISPLAYS` entries:
  the system library, and the v0.15.2 build through its wrapper.
  Use 80 ms / 10 Mbit, busy activity and `streaming-video=all`.
  The two should agree within the rig's noise. Confirm which
  library loaded, with `/proc/<qemu pid>/maps`, not by assuming.
- **Answer the codec question.** Why did phase 4's `all` runs
  send MJPEG (codec 1) when earlier pages report H.264, with the
  same Ryll (0d140b3)? Leads, in order:
  - Ryll's `pref_video_codec_type_sent`, and the codec order it
    sends;
  - whether the proxy relayed the message. The gate is
    `caps.rs:278-283`, so check what caps the client really sent
    on the phase 4 command line;
  - spice-server's own log at `SPICE_DEBUG_LEVEL`, which names
    the encoder it creates;
  - the difference between phase 4's command lines and the
    transcoding spike's, in `tools/shaped-link/run-matrix.sh`'s
    git history.

  Report the cause with evidence: a log line, a capture or a
  diff. If it is a kerbside bug, file an issue with the evidence
  and stop there; the fix is its own pull request.
- **Report** in at most 400 words: the script's interface, the
  neutrality numbers, and the codec cause.

**Step 2.** Needs step 1's script.

- **Reproduce the crash on 0.15.2.** Run the rig with
  `ACTIVITY_DELAY=0` and `streaming-video=all`, so the guest
  streams before Ryll connects
  (`docs/performance/streaming-rebaseline.md`, caveats). Count
  crashes over 20 connects. Take a backtrace from a core or from
  `gdb -p` on the host's qemu, with debug symbols from the
  container build.
- **Then v0.16.0 and master,** 20 connects each.
- **If master crashes,** find the root cause in
  `VideoStreamClipItem`'s lifetime against the newly connected
  client, and patch it in master's style. That means `red::shared_ptr`
  ownership and the RAII patterns of the recent `dcc` commits,
  such as 6774c046. Add a test under `server/tests/` if the
  existing harness can reach it, and say plainly if it cannot.
  The fix must take the reproducer to zero crashes in 20.
- **If master does not crash,** bisect `v0.15.2..master` with the
  reproducer as the test. Run each bisect step under `timeout`,
  and count a hung qemu as bad. Name the fixing commit and the
  first tag that contains it.
- **Stop for review** with the backtrace, the counts and the
  patch or commit.
- **Report** in at most 400 words.

**Step 3.** Patches against master (or master plus step 2's fix,
if there is one). Each patch must pass `meson test` through the
step 1 script. Each is a separate `git format-patch` file, in
spice-server's commit style: subject `area: summary`, a body
saying why, and `Assisted-by: Claude Opus 5.5` with no
`Signed-off-by` (decision 7).

- **Trace ring.** `TRACE_ITEMS_SHIFT` 3 to 6. The body should
  say what the ring is for and why stock qemu's column slivers
  overflow it (survey, finding 4).
- **60 fps ceiling.**
  - `MAX_FPS` 30 to 60. Check every user of `MAX_FPS` and
    `get_source_fps`, including the `input_fps = MAX_FPS * 2` at
    `video-stream.cpp:484` and the bitrate arithmetic in
    `gstreamer-encoder.c:610,1980`.
  - The guest also needs a 60 fps activity to show any effect.
    Add `busy60:60:3` to the step 4 matrix rather than changing
    the rig's defaults.
- **Vendor-neutral hardware probing.**
  - Probe the hardware plugins for any GPU with a render node,
    not only Intel's. Keep Intel's current option strings where
    they apply.
  - Give `va` options that suit radeonsi as well. Confirm
    `vah264enc` exists and encodes on this host first, with
    `gst-launch-1.0` on a test source.
  - A probe that finds a plugin which then fails to start must
    fall back to software, not leave the stream without an
    encoder. Test that fallback by hiding the render node from
    qemu, for example with an unprivileged mount namespace that
    binds an empty directory over `/dev/dri`. The plugin is then
    still registered, but cannot open a device.
- **Report** in at most 300 words, with the patch files' paths.

**Step 4.** One `run-matrix.sh` run:
- **Displays:** system 0.15.2, master, master plus each patch
  alone, and master plus every kept patch.
- **Profiles:** phase 4's
  - 20 ms / 50 Mbit;
  - 80 ms / 10 Mbit;
  - 80 ms / 5 Mbit;
  - 150 ms / 2 Mbit.
- **Activities:** idle, busy, heavy, and `busy60` for the fps
  rows.
- **Streaming:** `all` and `filter`.

Record, per cell:
- latency p50 and p95;
- qemu CPU;
- stream count and codec, from Ryll's log;
- for the encoder rows, whether the hardware encoder engaged,
  from spice-server's log, not assumed.

Write the tables to `upstream/spice/results/` in kerbside-patches,
generated by `summarise.py` or a sibling. Keep raw captures out
of the repository, as `upstream/README.md` requires. For each
patch, state whether it meets decision 5's bar, cell by cell.
Report in at most 400 words.

**Step 5.**
- **The kerbside-patches series.**
  - Assemble `upstream/spice/series/v1/` from the patches that
    met decision 5, with a cover letter that summarises the
    measurements and links the results.
  - Add `config.yaml` with `repo:
    https://gitlab.freedesktop.org/spice/spice.git`, `branch:
    master`, the verified `base_sha`, `current_series: v1` and
    `disposition: submit`.
  - Add `upstream/spice/README.md`, a "spice -- to be submitted
    by Michael" section in `upstream/README.md` (the policy
    evidence is survey finding 1), and the patches that were
    dropped, with why, in the project README.
  - Confirm the series applies with the README's `git am`
    recipe, and that `find . -maxdepth 2 -name config.yaml` is
    unchanged.
  - Open the kerbside-patches pull request.
- **The kerbside write-up.**
  - Write `docs/performance/spice-server-patches.md`: the codec
    answer, the crash answer, each patch's verdict with its
    numbers, and what a deployment gains from upgrading alone.
    Link it from `docs/index.md`, next to the other performance
    pages.
  - Update the master plan: the phase 5 section's outcome, the
    Execution row's `Merged` cell with the kerbside-patches
    merge, and Future work. Close the crash and codec items, and
    add H.265, the bitrate ramp if step 4 showed a reason, and
    the `streaming-video` recommendation with this phase's facts.
  - If the codec answer contradicts the earlier pages' H.264
    claims, correct them at their source.

## Risks and mitigations

- **The swapped library behaves differently from Debian's for
  reasons unrelated to any patch** (configure flags, a GStreamer
  mismatch). Step 1's neutrality check catches it before anything
  is measured. The management session reads those numbers before
  approving step 2.
- **The crash is timing-dependent and does not reproduce on
  demand.** Twenty connects with streams running is the bar for
  "reproduces". If 0.15.2 does not crash in 20, step 2 says so
  and stops. That is a result, not a failure to retry until the
  number looks right.
- **`vah264enc` does not work on this GPU,** or works only for
  some formats. Step 3 checks it with `gst-launch-1.0` before
  writing the patch. If it fails, the patch is still written, and
  the write-up says it could not be measured here.
- **60 fps doubles bandwidth on slow links.** Decision 5
  applies: a regression in any cell drops the patch unless it can
  be made conditional. The slow-link profiles are in the matrix
  for exactly this.
- **Ryll's codec preference does not reach spice-server through
  the proxy** (step 1). Decision 8 measures the encoder row
  directly against qemu, and the bug gets an issue.
- **The series ages before Mikal sends it.** Master is moving
  fast (survey, finding 2). `base_sha` records what it applied
  to. kerbside-patches' upstream plan owns the rebase check, as
  it does for qemu and Linux.
- **A patch is AI-assisted where upstream later declines that.**
  Finding 1 is practice, not policy. The cover letter discloses
  the assistance in its trailers, and Mikal decides whether to
  send.

## Definition of done

- `upstream/spice/rig/build-spice.sh <ref>` produces a library
  and a wrapper, and runs `meson test`. The neutrality run's
  system and v0.15.2 rows differ by less than the rig's
  run-to-run spread, as the results page states it.
- The codec cause is stated in the write-up with evidence (a log
  line, a capture or a diff). If it was a kerbside bug, an issue
  number is cited.
- Crash counts out of 20 are recorded for 0.15.2, 0.16.0 and
  master, and either a patch takes master to 0 of 20 or a
  bisected commit is named with its first tag.
- Each of the three patches has a verdict against decision 5, in
  a table generated from the run.
- In kerbside-patches:
  - `upstream/spice/series/v1/` applies cleanly with `git am` onto
    `config.yaml`'s `base_sha`;
  - `find . -maxdepth 2 -name config.yaml` lists the same files
    as before;
  - no patch carries a `Signed-off-by`.
- This phase changes no Kerbside product code:
  `git diff origin/develop...HEAD --stat -- kerbside rust` is
  empty.
- The master plan's Execution row records the kerbside-patches
  merge in `Merged`.

## Execution notes

None yet.

## Back brief

Before executing any step, back brief the operator. The points
that need an answer:

1. **Is the re-scope right** (decision 1)? It takes in the crash
   and the codec question, withdraws GLZ, and defers H.265 and
   the bitrate ramp.
2. **Is `disposition: submit` right for spice-server,** with Mikal
   sending (decision 7)? The alternative is `carry`, as with qemu.
3. **May this session open the kerbside-patches pull request, and
   the kerbside one?**
