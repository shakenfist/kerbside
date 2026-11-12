# SPICE performance phase 9: push audit of phases 6 and 7

Master plan: [PLAN-spice-performance.md](PLAN-spice-performance.md).

## Planning effort

This plan was written in a high-effort session. The master plan
gives the phase no effort level, only the push-audit shared block.
Review effort: medium. The judgment is almost entirely in the
range -- the survey found landed, unaudited work the master plan's
phase 9 section does not mention -- and in weighting the review by
blast radius rather than by line count. The steps themselves
follow the runbook.

## Scope

In scope:

- Running kerbside's `PUSH-AUDIT.md`, waves 1 and 2, over the two
  landings under *Audit range*: phase 6's follow-up (#701) and
  phase 7 (#716).
- The shared block's floor checklist, items 1 to 5, for kerbside.
- Deciding, for each `Future work` entry in this plan's phase
  files and the master plan, whether it has a live home; and
  listing those that do not (decision 5).
- Triaging every finding as blocking or advisory, with the reason,
  in this plan's *Outcome*.
- Filing problems that predate the plan as issues.

Out of scope:

- Fixing findings. They land in a follow-up pull request after
  this one merges (decision 4), which also marks the plan
  `Complete` if phase 2 has landed by then.
- Phases 1 to 5, and the kerbside-patches landings #1748 and
  #2024: audited by phase 6, which this phase cites rather than
  repeats (decision 1).
- ryll #406, audited by phase 6 step 6g under ryll's own runbook.
  Phase 7 landed nothing in ryll (survey finding 5), so no second
  repository is in range.
- Phase 8, which was abandoned and landed nothing.
- Wiring `tools/quic-bench/` into CI. Whether that should happen
  is a finding for triage; an audit phase does not change code
  (decision 2).
- Phase 2's dri-devel submission, which is still unsent and whose
  audit is the upstream review.

## Audit range

### kerbside

| Landing | Read as | Size | What it is |
|---------|---------|------|------------|
| 17a31ebf75 (#701) | `17a31ebf75^1..17a31ebf75` | 26 files, 736+/114- | Phase 6's follow-up: the fixes its own audit called for |
| e0f53fb04a (#716) | `e0f53fb04a^1..e0f53fb04a` | 20 files, 5084+/26- | Phase 7: the rig's loss term and the transport bench |

Both are merge commits, so each is read against its first parent,
which is the whole of what landed.

### Cited, not repeated

- Phases 1 to 5, kerbside: phase 6's audit, recorded in
  [its plan](PLAN-spice-performance-phase-06-push-audit.md)
  (2a34fe7ea9, #668).
- kerbside-patches #1748 and #2024: phase 6 step 6h, floor
  checklist.
- ryll fdb5ead5b4 (#406): phase 6 step 6g, under ryll's runbook.
- andris #56: audited in its own pull request body.

## What the survey found

**1. Phase 6's follow-up landed unaudited, and it is shipped
code.** This is the finding that reshapes the phase. The master
plan's phase 9 section says the phase "audits phase 7's
accumulated diff ... and cites phase 6 for phases 1-5". But phase
6's audit merged on 2026-10-31 as #668, and the follow-up pull
request it called for merged seven days later, on 2026-11-07, as
17a31ebf75 (#701). Nothing audited that follow-up: a grep for
`17a31eb` and `#701` across `docs/plans/` finds them only in the
master plan's `Merged` cell for phase 6. It is 736 insertions over
26 files and, unlike phase 7's, most of it ships --
`rust/kerbside-proxy/src/caps.rs` (+135),
`main.rs` (+95), `ackwindow.rs` (+61), `relay.rs` (+60),
`backend.rs` (+20), `kerbside/config.py` (+30) and
`tools/build-proxy-wheel.sh` (+49). The shared block is explicit
that the final phase audits the accumulated diff of every phase
rather than the last phase alone, precisely so that work landing
between audits is not missed. Corrected at source in the master
plan's phase 9 section and the `index.md` row as part of this
planning commit.

**2. Nothing automated compiles or tests the phase's Rust.**
`tools/quic-bench/` is 1,162 lines of Rust outside
`Cargo.lock`, and no repository gate touches it.
`.github/workflows/rust.yml` triggers on `rust/**` plus four named
`tools/` scripts, none of them this one, and runs with
`working-directory: rust/kerbside-proxy`; nothing anywhere in
`.github/` mentions `quic-bench`; there is no Rust hook in
`.pre-commit-config.yaml`; and wave 1's own gates are tox, meaning
flake8 and py3. The crate is a standalone cargo project -- there
is no root `Cargo.toml` and it is not a workspace member -- whose
only Rust gate is a hand-run `make lint`, `make test` and
`make mutants` in Docker. Its shell and Python are gated:
shellcheck matches `^(tools|demo)/` and flake8 matches `^tools/`,
so `run-bench.sh`, `mutation-check.sh` and `summarise.py` are
covered. Wave 1 would therefore pass vacuously on the Rust, which
is why decision 2 names a substitute gate.

**3. A phase-1 page still states what phase 7 disproved.**
`docs/performance/proxy-backpressure.md:253` says BBR "was not
measured" because "This host's kernel has only `reno` and `cubic`
loaded". Phase 7 found the module present on disk and the master
plan carries a dated correction, but the page itself was never
revisited. The page then predicts that "On these profiles BBR
could only trim the bottleneck queue (about 20 ms at 20 ms RTT,
one BDP), which is small next to the ACK-window backlog", where
phase 7 measured 9.27 Mbit against Cubic's 1.64 at 1% loss and an
interactive p95 of 104 ms against 171 ms at no loss. Those numbers
are from 80 ms / 10 Mbit and 150 ms / 2 Mbit, not phase 1's
profiles, so whether the prediction is falsified or merely out of
scope is a question for the audit rather than a settled finding.
This is the exact class the shared block warns about: the page an
earlier phase made wrong that a later phase never revisited.

**4. The page that owns the rigs does not mention the new one.**
`docs/testing.md` documents `tools/shaped-link/` at length and was
not touched by phase 7. It mentions `PROFILES=0:0` but says
nothing about the optional third `:loss_pct` field phase 7 added,
and `tools/quic-bench/` appears nowhere outside `docs/plans/` and
the two measurement pages. A reader looking for the rigs in the
page that teaches them will not learn the bench exists.

**5. The premise that holds.** Phase 7 landed nothing in ryll:
its diff touches neither `tools/shaped-link/ryll-surface-drawn-rect.patch`
nor `build-ryll.sh`'s `RYLL_REF` pin, both of which its execution
notes record as deliberately untouched once steps 5a, 5b and 6
became void. Phase 8 landed nothing at all. So the master plan's
"all of it in Kerbside" is correct, even though its scope is not.

**6. Two `Future work` entries have no home.**
`gh issue list --state all --search` finds no issue for the
kernel-BBR finding or for the missing `ticket-valid-until` in the
`.vv` template, both of which phase 7 records as worth one. Phase
9 is the plan's last phase, so an entry with no issue dies with
the plan when it retires.

**7. Floor item 3 looks clean mechanically.** The addresses in the
files phase 7 added are RFC1918 rig addresses inside unprivileged
namespaces -- 10.77.0.x for `shaped-link`, 10.78.0.x for
`quic-bench`, deliberately distinct -- plus `0.0.0.0` and
loopback. No home or scratchpad paths, no hostnames. The audit
confirms rather than discovers this, and extends it to #701.

## Decisions

1. **The range is #701 and #716, not phase 7 alone.** Survey
   finding 1. Auditing phase 7 by itself would leave shipped
   proxy code permanently unaudited, which is the failure the
   shared block's accumulated-diff rule exists to prevent. Phases
   1 to 5 are cited rather than re-read: they were audited, the
   audit's findings were fixed, and re-reading 5,000 lines of
   already-audited diff would buy less than reading the 736 lines
   that fixed it.

2. **The crate's own `make` targets stand in for wave 1's Rust
   gate.** Survey finding 2 means wave 1 cannot speak for
   `tools/quic-bench/`. Step 9a runs `make lint`, `make test` and
   `make mutants` in Docker and reports them as the substitute,
   naming them as hand-run rather than enforced. The back brief
   settled what the finding then recommends: wire the crate into
   `rust.yml`, with the wiring itself follow-up work rather than
   part of this pull request. The argument against is the one
   review round one on #716 made when it declined CI wiring for
   `summarise.py` -- the crate is a measurement tool for a closed
   experiment. The argument that won is phase 7's own *Future
   work*, which names `tools/quic-bench/` as the bench to re-run
   the kernel-BBR question with: a tool with a future needs a
   gate.

3. **Weight the review by blast radius, not line count.** #716 is
   5,084 insertions of standalone tool that never enters the wheel,
   never runs unattended and has no untrusted input. #701 is 736
   insertions, most of them in the shipped proxy, including 135
   lines in `caps.rs`, which parses a client's link message before
   the backend sees it. The security step reads #701 at high
   effort on opus; `quic-bench`'s security question is what the
   tool does to the host that runs it.

4. **Findings are not fixed here.** The shared block puts them in
   their own pull request against the default branch. That
   includes survey findings 3 and 4, which are findings this phase
   records rather than edits it makes.

5. **Every `Future work` entry gets checked for a live home.**
   Phase 6 step 6e set the precedent. Because phase 9 is the last
   phase, the check covers all six phase files and the master
   plan, and anything without a home is listed in *Outcome* for
   Michael to file. The audit does not file issues without
   showing him the wording first.

6. **Phase 9 marks itself `Complete` and the plan stays
   `In progress`.** A push-audit phase closes itself out in its
   own pull request and records no `Merged` cell. The plan cannot
   reach `Complete` while phase 2's kernel fix is unsubmitted, so
   the plan's own status stays `In progress` with phase 2 named as
   the reason.

7. **The record goes in this plan's *Outcome*.** One place, as
   phase 6 did, so a reader finds the verdicts next to the range
   they were reached against.

## Step plan

Step 9a is a gate: wave 2 is only worth spending on if wave 1
passes, as the runbook says. Steps 9b to 9e are read-only readers
and run in parallel once 9a has passed. 9c works on a copy of the
tree in its own scratch directory, so it does not collide with
the others.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 9a | low | sonnet | none | Wave 1, kerbside, over both landings in *Audit range*, oldest first: run `AUDIT_RANGE="$M^1..$M" tools/audit/wave1.sh` with `AUDIT_PATHS` unset for `M` of `17a31ebf75` then `e0f53fb04a`, and report each exit code with its advisory output (codes are in `PUSH-AUDIT.md` under Wave 1). Do not use `plan-range.sh`, and never change a range to make a run pass; if either run exits 6, stop and report. Then the substitute Rust gate decision 2 names, because wave 1's gates are tox and cannot see `tools/quic-bench/` (survey finding 2): in `tools/quic-bench/`, run `make lint`, `make test` and `make mutants` under `timeout 1800` each, in Docker, and report each one's result with the test count and the killed/survived mutant counts. A surviving mutant is a finding. Confirm independently, with `grep` over `.github/` and `.pre-commit-config.yaml`, that no automated gate covers that crate's Rust, and say what you checked. Finally, for `rust/kerbside-proxy`, find `rust.yml`'s push run on `17a31ebf75` with `$HOME/bin/ci-status shakenfist/kerbside runs --branch develop --limit 200` and report its conclusion and run ID. Report in under 350 words. |
| 9b | medium | sonnet | none | Wave 2 mechanical, plus the 2a code-quality brief in `PUSH-AUDIT.md`, over both landings. Run `AUDIT_RANGE="$M^1..$M" tools/audit/wave2-mechanical.sh` once per landing and report its output; it never exits non-zero on findings. The shared blocks named in 2a bind: `python-version-discipline`, `comment-proportion`, `source-file-size` and `plan-references-in-code`. Material for the size block: `tools/quic-bench/src/main.rs` (474), `run-bench.sh` (417), `summarise.py` (339), `src/workload.rs` (293), `src/quic.rs` (276), and in #701 `caps.rs` and `main.rs` as they now stand. The cross-phase question, which is the one worth your time: `tools/shaped-link/run-matrix.sh` and `tools/shaped-link/summarise.py` were changed by both #701 and #716, and `run-matrix.sh` is 700-odd lines across five phases now -- does it carry modes, profile fields or code paths that no caller and no page uses any more, and did #716's loss term leave a path that only an old invocation reaches? Second: `tools/quic-bench/summarise.py` and `tools/shaped-link/summarise.py` are sibling scripts in the same repository; do they duplicate logic that should be shared, or is the duplication deliberate? Answer that one on the evidence, not on principle. Report blocking or advisory per finding, with file and line, in under 450 words. |
| 9c | medium | opus | none | 2b test review over both landings, under the `functional-test-coverage` shared block. Work on a copy of the tree in your scratch directory; never mutate the worktree, and restore from the copy rather than with `git checkout <dir>`. Each mutant runs under `timeout`, and a timeout counts as killed. #716 added nine unit tests in `tools/quic-bench/src/main.rs` and a mutation script, `tools/quic-bench/mutation-check.sh`, which claims seven mutations and seven kills. Re-run that script and report its result; then answer, per test, whether it fails when the property it names is broken, and name the mutation you used. Then the question the script does not answer: `summarise.py` is the code that produced every published table, and it has no tests at all -- list the paths in it that a published number passed through and say which could change a published figure without any test noticing. Note that review round one on #716 declined to add fixture tests for it, on the grounds that the independent recomputation in the phase's execution notes is the real check; say whether you agree, on the evidence. For #701, check the guards it added: `caps.rs`'s capability rewriting including a malformed or oversized link message, `ackwindow.rs` holding the backlog at 2W+1, and `config.py`'s validation. Run `make test` in a copy's `rust/kerbside-proxy/` under `timeout 900`, at most eight Rust mutants in all. Keep the mutations in a script and give its path. Report in under 450 words. |
| 9d | high | opus | none | 2c documentation review over both landings, under its four shared blocks (`readme-discipline`, `llm-doc-discipline`, `diagram-discipline`, `plan-phase-references`). Three questions first, each of which this plan records as a survey finding you must confirm or refute independently rather than accept. One: `docs/performance/proxy-backpressure.md` around line 253 says this host's kernel has only `reno` and `cubic` loaded, and predicts BBR could only trim about 20 ms of queue; phase 7 measured 9.27 Mbit against 1.64 at 1% loss and p95 104 ms against 171 ms at no loss, on 80 ms / 10 Mbit and 150 ms / 2 Mbit. Read both pages and the master plan's dated correction, and say which statements are now false, which are merely about different profiles, and which page owns each claim. Two: `docs/testing.md` teaches `tools/shaped-link/` but was not touched by #716 -- does it need the loss term and a pointer to `tools/quic-bench/`, or does the measurement page own that? Three: check every `Future work` entry in all six `PLAN-spice-performance-phase-*.md` files and the master plan for an issue or somewhere live that still tracks it, reading GitHub only with `gh issue view`, `gh issue list` and `gh pr view`; the kernel-BBR and `ticket-valid-until` entries are expected to have none. Then hold the pages together: the eleven pages under `docs/performance/`, `docs/index.md`, `docs/testing.md`, `ARCHITECTURE.md` and `AGENTS.md`. Does any page still state something a later phase overturned, beyond question one? Do `docs/index.md`'s two new entries describe what the pages say? Grep `README.md`, `AGENTS.md`, `ARCHITECTURE.md` and `docs/` outside `docs/plans/` for "phase <number>" and for named people. Report blocking or advisory per finding, in under 550 words. |
| 9e | high | opus | none | 2d security review, weighted by decision 3. The material that ships is #701: `caps.rs` (+135), which parses and rewrites an untrusted client's link message before the backend sees it; `ackwindow.rs` (+61) and `relay.rs` (+60), which count client ACKs and server messages; `main.rs` (+95); `backend.rs` (+20); `kerbside/config.py` (+30); and `tools/build-proxy-wheel.sh` (+49). Check every length, count and offset taken from the wire for bounds and overflow, what a truncated or oversized link message does, unbounded per-connection state, whether a client-supplied value reaches a log line, and whether an out-of-range config value reaches `setsockopt` unchecked. The `path-traversal-review` shared block binds. For #716 the question is different, because nothing in it ships, enters the wheel or takes untrusted input: it is what the tool does to the host that runs it. Read `tools/quic-bench/run-bench.sh` and #716's changes to `tools/shaped-link/run-matrix.sh` for commands run as root, `tc` or namespace state left behind on failure, temporary paths another user on the host could pre-create before the script writes them, and the TLS key material the bench generates -- the script does `chmod 700` on its TLS directory and checks certificate validity, so say whether that is sufficient and whether the key can be read by another user at any point. Then the floor checklist, items 2 to 5, over both landings, each with a verdict or a sentence saying why it does not apply: 2, does anything added run unattended, and does it report its own failure where a human sees it? 3, did either landing put a secret, token, private hostname, address other than loopback or documentation ranges, username or home or scratchpad path into this public repository -- including the figures and command output quoted in the two new pages? 4, did either remove or rename anything with a consumer left, checked by grep across this repository and `../ryll`, with the greps stated? 5, this repository publishes a wheel and images, so does a broken change in #701's `build-proxy-wheel.sh` fail closed? Report severity, file, line, class and fix per finding, in under 550 words. |
| 9f | high | (management session) | n/a | Triage and record. Take 9a to 9e's reports and reproduce every finding against the tree before accepting it; an agent's report is model output, not evidence. Classify each as blocking or advisory and decide: fix in the follow-up pull request, decline with the reason in writing, or file as an issue if it predates the plan (`git log -S` or blame against the two landings). Show Michael the wording of any issue before filing it. Give a verdict on each floor item 1 to 5 for kerbside. Record the back brief's recommendation that `tools/quic-bench/` be wired into `rust.yml`, and say whose follow-up that is. Write it all into this plan's *Outcome*, including the `Future work` entries with no home, and run the private-data probe set over the text this phase adds before committing. Mark phase 9 `Complete` in the master plan and `docs/plans/index.md` with no `Merged` cell, and leave the plan `In progress`, naming phase 2 as the reason (decision 6). Commit subject: "Record the phase 6 and 7 push audit." |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| The survey's three doc findings are mine, and an agent told they are findings will confirm them rather than check them. | 9d's brief states each as a claim to confirm or refute independently, names the pages that own each claim, and asks which statements are merely about different profiles. 9f reproduces before accepting. |
| #701's range was recorded in a `Merged` cell but never audited, so the same could be true of a landing I have not noticed. | 9a's floor item 1 verdict covers every recorded landing in the plan, not just the two in range, and reports any whose form or audit it cannot account for. |
| A surviving mutant in `mutation-check.sh` would mean #716's tests do not hold, after a review round that cited them. | 9a reports killed and survived counts explicitly and a survivor is a finding; 9c re-derives the kills independently rather than trusting the script. |
| The crate has no automated gate, so a later change to it breaks nothing visibly. | Named as survey finding 2, and the back brief settled it: the audit recommends a CI gate, so the gap leaves the plan as a recommendation rather than an observation. |
| An audit phase quietly turns into a fixing phase, as the material is small and the fixes look cheap. | Decision 4. Findings land in a follow-up pull request; 9f records, and does not edit. |
| Phase 2 is still open, so the plan cannot complete and the audit could be read as closing it. | Decision 6: phase 9 `Complete`, plan `In progress` with phase 2 named. |

## Definition of done

- `AUDIT_RANGE` for each of `17a31ebf75^1..17a31ebf75` and
  `e0f53fb04a^1..e0f53fb04a` was run through `tools/audit/wave1.sh`
  and `tools/audit/wave2-mechanical.sh`, with every exit code
  recorded in *Execution notes*, and no range was altered to make
  a run pass.
- `make lint`, `make test` and `make mutants` in
  `tools/quic-bench/` are recorded with their test count and
  their killed and survived mutant counts. Any survivor appears
  in *Outcome* as a finding.
- Each of the nine unit tests #716 added is listed with the
  mutation that kills it, or named as unguarded.
- *Outcome* gives a verdict, or a sentence saying why it does not
  apply, for each of floor items 1 to 5, for kerbside.
- *Outcome* states, for `docs/performance/proxy-backpressure.md`'s
  BBR bullet, which of its statements are false, which are about
  other profiles, and which page owns the claim -- with file and
  line.
- Every `Future work` entry in the six phase files and the master
  plan is listed in *Outcome* with its live home, or named as
  having none. The kernel-BBR and `ticket-valid-until` entries
  carry wording Michael can file as issues.
- *Outcome* recommends wiring `tools/quic-bench/` into `rust.yml`
  and names whose follow-up that is.
- Every finding is classified blocking or advisory and dispositioned
  fix, decline or file, with the reason, in *Outcome*.
- `grep -rn 'phase [0-9]'` over `README.md`, `AGENTS.md`,
  `ARCHITECTURE.md` and `docs/` outside `docs/plans/` finds no
  plan citation either landing introduced.
- The private-data probe set was run over the text this phase
  adds, and *Execution notes* says so.
- Phase 9 reads `Complete` in both the master plan's Execution
  table and `docs/plans/index.md`, with no `Merged` cell, and the
  plan's own status reads `In progress` with phase 2 named as the
  reason.

## Future work

- Nothing yet. Findings the audit declines or defers are recorded
  in *Outcome* with the reason, and anything worth tracking
  beyond this plan becomes an issue at step 9f.

## Execution notes

Entries are added as the steps run, per `PLAN-TEMPLATE.md`: the
date with its timezone, any step run out of order, any decision
that changed, and the wave exit codes.

- **2026-11-12, AEDT.** The survey's count of the crate's Rust was
  wrong in the first draft of this plan: `tools/quic-bench/src/`
  is 1,162 lines, not about 1,500, which the planning commit also
  said. Corrected here and in `index.md` before any step ran.
- **2026-11-12, AEDT.** Back brief questions 2 to 4 answered: the
  audit recommends a `rust.yml` gate for the crate; 9f lists the
  two homeless `Future work` entries with filing wording rather
  than filing them; and this session may push and open the pull
  request.
- **2026-11-12, AEDT.** Back brief question 1 is answered ahead of
  implementation: Michael confirmed the widened range, phase 6's
  follow-up #701 together with phase 7's #716, in preference to
  auditing phase 7 alone or re-auditing phases 1 to 7. Decision 1
  and the corrected master plan section stand as written.
  Questions 2 to 4 are still open.

## Outcome

To be written by step 9f.

## Back brief

My understanding: this is the plan's last phase, and it audits
what phases 6 and 7 landed in kerbside -- #701 and #716, each
read as a merge against its first parent -- citing phase 6 for
phases 1 to 5 and ryll #406. Step 9a is a gate; 9b to 9e then run
in parallel as read-only readers; 9f triages, records and closes
the phase out. Findings land in a follow-up pull request, not
here. Points needing your answer before 9a runs:

1. **The range.** The survey found phase 6's follow-up (#701,
   736 insertions, mostly shipped proxy code) landed seven days
   after the audit that called for it and was never audited. I
   have put it in range and corrected the master plan's phase 9
   section, which said phase 7 alone. Do you agree, or would you
   rather phase 9 audit phase 7 only and #701 be handled
   separately?
2. **The Rust gate.** Answered: the audit recommends wiring
   `tools/quic-bench/` into `rust.yml`, and the wiring is
   follow-up work (decision 2).
3. **The two unfiled `Future work` entries** -- the kernel-BBR
   sysctl finding and the missing `ticket-valid-until`. Answered:
   step 9f lists both with wording Michael can file, and files
   nothing itself (decision 5).
4. **The pull request.** Answered: this session may push and open
   it when the phase is done, as it did for phase 7. Landing
   stays Michael's.
