# Consistency audit compliance -- phase 6: push audit

Phase 6 of [PLAN-consistency-audit.md](PLAN-consistency-audit.md).
Runs `PUSH-AUDIT.md` over the accumulated work of phases 1 to 5,
and records the result. It is the last phase of the plan.

## Planning effort

Planned at high effort in the management session. The master
plan's *Planning effort* section said "Phase 5 follows
`PUSH-AUDIT.md`", which was written when the plan had five
phases; the push audit is phase 6 and that sentence is
corrected at source by this phase's planning commit (survey
finding 7).

High rather than medium for one reason: the audit range is not
the one the master plan's sketch names, and getting a range
wrong is the failure mode that makes a push audit worthless.
`PUSH-AUDIT.md` says so itself -- a branch whose work has
merged gets an empty diff and a vacuous pass. Deciding the
range, and proving it against the tree, is most of the
planning here.

The execution steps are mostly low and medium effort, because
this plan's blast radius is documentation, CI workflows and
shell tooling rather than shipped Python. Two steps are high:
the security review, which has real material, and the
management triage.

## Scope

**In scope.** Executing `PUSH-AUDIT.md`'s two waves over the
recorded landings of phases 1, 2, 4 and 5 in this repository;
reviewing phase 3's upstream landing under
`shakenfist/development`'s own runbook; giving a verdict on
each item of the `plan-push-audit-phase` floor checklist;
recording the outcome in this plan; and correcting the master
plan where this phase's survey found it wrong.

**Out of scope.**

- **Fixing anything the audit finds.** Findings land as their
  own pull request against `develop`, per the
  `plan-push-audit-phase` block. This phase's pull request
  records; it does not remediate.
- **The human review backlog (#227).** Master plan decision 5
  draws that boundary and this phase does not reopen it. The
  `review-coverage` check fails today at 89 of 356 in-scope
  files reviewed, 267 outstanding against a threshold of 5,
  and is expected to keep failing. See decision 4.
- **Re-vendoring sfui.** The `sfui-vendor` check also fails
  today, and for a reason that is not a defect in this plan's
  diff. See decision 4.
- **Re-fixing the mermaid lane's fork-pull-request exposure.**
  It was a genuine defect in what phase 5 landed, and it has
  already been remediated on `develop`. The audit confirms the
  remediation and records the finding. See decision 5.
- **Anything in the four mermaid-lane commits that landed
  after phase 5.** `45af922`, `63920cf`, `c053cc3` and
  `3db6242` are not this plan's work; they are template
  re-syncs and a re-vendor. They matter only as evidence that
  a finding is already closed.

## Audit range

Phases landed between 2026-08-29 and 2026-09-04, and
unrelated work landed on `develop` between them, so there is
no single `first..last` range that covers the plan without
sweeping in other people's commits. Each phase landed as a
merge commit, so each is read against its first parent
(decision 1).

### kerbside

| Merge | PR | Date | Phase | What landed |
|-------|----|------|-------|-------------|
| `cbca9b1` | #376 | 2026-08-29 | 1. Shared blocks, vendor stamp, settings | 975 insertions over 6 files: four shared blocks into `PLAN-TEMPLATE.md` and `PUSH-AUDIT.md`, the one-line `kerbside/api/static/sfui/.sfui-commit` stamp, plan files and `docs/plans/index.md` |
| `5f3c80c` | #380 | 2026-08-30 | 2. Retire the comment addresser | 278 insertions, 1,470 deletions over 15 files: deletes `.github/workflows/pr-address-comments.yml`, `tools/address-comments-with-claude.sh`, `tools/render-review.py`, `tools/review-schema.json` and `kerbside/tests/unit/test_render_review.py`; edits `.github/workflows/pr-re-review.yml`, `tools/shellcheck-wrap.sh`, `tools/flake8wrap.sh`, `.claude/CLAUDE.md`, `REVIEWS.md` and the two `.vscode/` weAudit sidecars |
| `16e6173` | #382 | 2026-08-31 | 3. Skillsaw detection (plan only here) | 239 insertions over 3 files, all `docs/plans/`. No shipped file changed. The code landed upstream; see below |
| `ade2788` | #388 | 2026-09-01 | 4. Review scope and session scaffolding | 607 insertions over 5 files: `.vscode/review-scope.toml` (new), `docs/development.md`, plan files and the index |
| `54e8d08` | #398 | 2026-09-04 | 5. Diagram discipline and mermaid linting | 608 insertions over 9 files: `tools/mermaid-lint.sh` (new, 124 lines), `.github/workflows/mermaid-lint.yml` (new), the `diagram-discipline` block in `PUSH-AUDIT.md`, `.github/actionlint.yaml`, `docs/testing.md`, `.claude/CLAUDE.md`, plan files and the index |

Read each with `git diff <merge>^1..<merge>`. Across the five,
the shipped surface is: no Python added (one Python test file
deleted), one new shell script, one new and one edited
workflow, one deleted workflow, two edited shell wrappers, one
new TOML configuration, and documentation.

### Other repositories

Phase 3's code landed in `shakenfist/development` as
`223373f9d61e838242a17a447c08003c5ff5879a`, PR #73, merged
2026-08-31: a third route in `check_llm_context_lint_ci()`
matching `^\s*skillsaw\b`, plus tests in
`scripts/test_audit_check.py`.

The `plan-push-audit-phase` block says a phase that landed in
another repository "is audited against that repository's
default branch, as part of the pull request that lands it; the
plan's own push-audit phase cites that audit rather than
re-running it." There is no such audit to cite:
`shakenfist/development` does carry a `PUSH-AUDIT.md`, but PR
#73's body has no audit section -- it has *Why*, *What
changed*, *Regression evidence* and *Known narrowness*. Step
6g closes that gap rather than citing an audit that does not
exist (decision 3).

## What the survey found

Surveyed 2026-11-04 against `develop` at `014b60d`. The
master plan's phase 6 sketch was written before phase 5
existed and three of its claims no longer hold.

**1. The range is four phases in this repository, not three.**
The sketch says "the accumulated diff of phases 1, 2 and 4".
Phase 5 landed on 2026-09-04 as `54e8d08` and is squarely in
scope -- it is the phase with the largest shipped surface and
the only security finding. Corrected at source.

**2. Phase 3 did land something here, and the `Merged` cell
records the wrong thing.** The sketch and the index row both
say nothing in kerbside moved. In fact `16e6173` is a kerbside
merge commit carrying 239 insertions across three
`docs/plans/` files. Nothing *shipped* moved, which is what
the sketch meant, but the Execution table's `Merged` cell for
phase 3 reads `16e6173` -- the local plan-only merge -- where
the `plan-push-audit-phase` block asks a cross-repository
landing to record `<repo> <sha> (#pr)`. The cell names a
commit whose diff contains none of phase 3's code. Corrected
at source to record both.

**3. The ordering hazard the sketch names is now backwards.**
The sketch says the audit "must be run from the version of
[`PUSH-AUDIT.md`] that phase 1 produced", because phase 1 adds
three criteria to it. That was sound when phase 1 was the only
phase to touch the file. Since then phase 5 added
`diagram-discipline` to the same file (`a7b54a7`), and
`PLAN-TEMPLATE.md`'s `plan-push-audit-phase` block has moved
from the version phase 1 adopted to v4 (`fc0f277`, `a259022`).
Today's copy on `develop` is a strict superset of phase 1's
and is the version the repository is actually held to. Run
from today's copy (decision 2). Corrected at source.

**4. Two audit checks fail today, neither of them a defect in
this plan's diff.** `python3 scripts/audit-check.py
--repo-path <kerbside> --repo-name kerbside` from a
`shakenfist/development` checkout reports 67 checks: 54 pass,
11 not applicable, 2 fail, 0 error.

- `review-coverage`: 89 of 356 in-scope files reviewed, 267
  needing review against a threshold of 5. This is #227,
  which master plan decision 5 deliberately leaves to the
  label.
- `sfui-vendor`: the vendored copy is 10 commits behind
  canonical. This is decay rather than regression, and the
  measurement is unusually clean: phase 1 set the stamp to
  `c3f65ae`, it has been re-vendored five times since, most
  recently *yesterday* (`3db6242`, 2026-11-03, at `d8b1c7d`),
  and sfui's `develop` moved 10 commits in the one day since
  (`d8b1c7d..ab93e07`). The audit has filed and closed this
  same issue four times -- #507, #516, #560 and #606, the
  last closed 2026-11-03.

**5. Phase 5 shipped a real security defect, found outside the
audit and already fixed.** `54e8d08` added
`.github/workflows/mermaid-lint.yml`, which ran the
checkout's own `tools/mermaid-lint.sh` on a self-hosted VM
runner. The script is bash on the runner, outside the
container that `--network none` and the read-only mount
constrain, so a fork pull request that edited the script
started the lane; the checkout also persisted `GITHUB_TOKEN`
into a third-party container that never used it. That was
filed upstream as `shakenfist/development`#323 and fixed here
by `c053cc3` (2026-10-25), which adds a
`head.repo.full_name` guard and stops persisting the token.
This is the finding the push audit's 2d review exists to
catch, and the plan's own audit phase did not catch it
because it runs seven weeks after the code landed. Worth one
sentence in the outcome (decision 5).

**6. The audit tooling is present and already handles a
merged range.** `tools/audit/wave1.sh`,
`wave2-mechanical.sh` and `plan-range.sh` all exist and read
`AUDIT_RANGE` and `AUDIT_PATHS` from the environment.
`tox -eshellcheck` exists, which matters here because the
shell is the largest body of new executable material.

**7. The master plan's *Planning effort* section is off by
one.** It says "Phase 5 follows `PUSH-AUDIT.md`", written
when the plan had five phases. Corrected at source.

**Where the sketch was right.** Phase 1 did add exactly three
criteria to `PUSH-AUDIT.md` -- `python-version-discipline`,
`functional-test-coverage` and `path-traversal-review`, at
lines 218, 370 and 596 of today's copy -- and the ordering
hazard it worried about is real, just resolved in the other
direction. Phase 3's code genuinely does belong to another
repository's audit.

All four corrections (findings 1, 2, 3 and 7) are made in the
master plan and `docs/plans/index.md` by this phase's planning
commit, so a later step does not redo them.

## Decisions

**Decision 1 -- audit each phase against its merge commit's
first parent, not a single derived range.** Phases 1 to 5
landed over seven days with unrelated work between them, and
they share paths with other plans: `docs/plans/index.md`,
`.claude/CLAUDE.md` and `PUSH-AUDIT.md` were all touched by
other work in that window. A single `first..last` range, or
`plan-range.sh`'s derived range and path set, would therefore
audit commits this plan did not make -- and would do so
silently, which is the expensive kind of wrong. Five exact
diffs cost five script runs instead of one.

So the mechanical waves run once per merge with
`AUDIT_RANGE="$M^1..$M"`, oldest first, and `plan-range.sh`
is not used. This follows the precedent set by
`PLAN-spice-performance-phase-06-push-audit.md`, which made
the same call for the same reason.

The `plan-push-audit-phase` block warns that auditing one
phase at a time misses what the phases did to each other, and
that warning is respected rather than sidestepped: the
*judgment* steps (6b, 6c, 6d, 6e, 6f) read all five diffs
together as one body of work, and each carries named
cross-phase questions. The split is mechanical-per-merge,
judgment-over-the-union.

**Decision 2 -- execute today's `PUSH-AUDIT.md`, not phase
1's.** Survey finding 3. The alternative -- checking out
`cbca9b1`'s copy and working from that -- would run a
checklist that is missing `diagram-discipline`, which is the
block most relevant to phase 5, and would use a superseded
version of the floor checklist. Today's copy is a superset of
phase 1's in every criterion that matters here. The sketch's
hazard was that phase 1 *changed* the checklist, and the
answer is to use the newest version rather than the oldest.

**Decision 3 -- phase 3's upstream landing gets a scoped
review here, because there is no upstream audit to cite.**
Survey finding in *Other repositories*. The block's intent is
that a cross-repository landing is not audited twice; it
assumes the landing pull request audited itself, and #73 did
not. Two options: record "no audit was run upstream" and
leave floor-checklist item 1 unsatisfiable, or review the one
small diff under `development`'s own runbook. The diff is a
regex, a helper call and a test file, so the second costs one
sonnet step and makes item 1 answerable. Step 6g does it, and
reports findings against `development` rather than fixing
them here.

**Decision 4 -- the two live audit failures are recorded as
out of scope, with different reasons, and the sfui success
criterion is reworded rather than satisfied.** This is the
decision most likely to be argued with, so the reasoning is
set out in full.

`review-coverage` is easy: master plan decision 5 already
decided it, in writing, and #227 owns it. Nothing changes.

`sfui-vendor` is the awkward one, because the master plan's
*Success criteria* contain this line:

> `kerbside/api/static/sfui/.sfui-commit` names the commit at
> sfui's `develop` HEAD, and `tools/vendor.sh --check` from a
> checkout at that commit reports no difference.

As written, that criterion can never be durably true. It was
true at `cbca9b1`, and false again as soon as sfui took its
next commit. Survey finding 4 measures the cycle: five
re-vendors since phase 1, four filed-and-closed audit issues,
and a stamp that went stale within a day of the most recent
re-vendor. A plan cannot hold it closed, and re-vendoring
inside this phase would be worse than leaving it: the audit's
own commit would become part of the diff the audit is
auditing, and the check would fail again tomorrow regardless.

So this phase does not re-vendor. It reworks the criterion to
say what is actually checkable -- that the stamp was verified
against canonical at a named commit during phase 1, and that
the standing decay is owned by the recurring `sfui-vendor`
consistency issue rather than by this plan -- and records the
current measurement. The parallel with the master plan's own
*Future work* note on review coverage ("review coverage decays
with every merge ... Neither this plan nor the reading
sessions that follow it stop the backlog regrowing") is
exact, and the honest conclusion is the same one.

The counter-argument is that a plan should not edit its own
success criteria at the end to match what it achieved, and in
general that is right. What makes it acceptable here is that
the criterion is not being weakened on the thing it was
written to guarantee: phase 1 did re-vendor, that was
verified by byte-for-byte comparison at the time, and the
fact is preserved. What is being removed is a standing
obligation on a moving target that the plan never had the
means to meet. If Mikal disagrees, the alternative is a
one-line re-vendor commit in the follow-up pull request and a
criterion that is green on the day it merges -- which is a
defensible choice, just not an honest one about what the
criterion means.

**Decision 5 -- the mermaid lane's fork exposure is recorded
as confirmed-and-remediated, not reopened.** Survey finding 5.
Step 6f confirms three things rather than one: that the
exposure was genuinely present in what `54e8d08` landed, that
`c053cc3` and `63920cf` fully close it on `develop` today,
and that nothing else in the five diffs has the same shape.
Re-fixing is not available -- the fix is already merged -- and
pretending the audit found it first would be false. The
outcome records it as a finding against phase 5 that a
timelier audit would have caught, which is the only durable
value left in it.

**Decision 6 -- if the audit finds nothing further, phase 6
closes itself out in its own pull request, with no `Merged`
cell.** The `plan-phase-landing` and `plan-push-audit-phase`
blocks both require this: a push-audit phase has no later
phase to record its merge commit, so it marks itself
`Complete` in the master plan and the index as part of its own
pull request. If the audit does find something that needs
fixing, the findings pull request lands first and the plan
stays `In progress` until every finding is fixed or declined
in writing here.

Whether the *plan* reaches `Complete` is a separate question
from whether the *phase* does, because of decision 4:
`review-coverage` will still be failing. Master plan decision
5 anticipated exactly this and says the plan can complete with
it failing. Step 6h sets the plan's status to `Complete` on
that basis, and says so in the row.

## Step plan

All implementation is done by sub-agents, per the master
plan's execution model; the management session reviews,
triages and commits. Steps 6a to 6g are independent and can
be spawned in parallel. Every step reports in the stated word
budget, and none of them fixes anything.

`$M` below means each of `cbca9b1`, `5f3c80c`, `ade2788` and
`54e8d08`, oldest first. `16e6173` is excluded from the
mechanical runs because its diff is three `docs/plans/` files
and wave 1 has nothing to say about it; it is read by 6e.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 6a | low | sonnet | none | Wave 1, mechanical. For each of `cbca9b1`, `5f3c80c`, `ade2788`, `54e8d08`, oldest first, run `AUDIT_RANGE="$M^1..$M" tools/audit/wave1.sh` with `AUDIT_PATHS` unset, from the repository root. Report each exit code and its advisory output; the code table is in `PUSH-AUDIT.md` under *Wave 1*. Do **not** use `tools/audit/plan-range.sh` (decision 1), and never widen or alter a range to make a run pass. If any run exits 6 the range did not resolve -- stop and report. Expect the Python gates to have little to say: this plan added no Python and deleted one test file (`kerbside/tests/unit/test_render_review.py`, in `5f3c80c`), so say explicitly whether `tox -eflake8` and `tox -epy3` had any material from each merge. The shell is the real material, and `wave1.sh` does not cover it: also run `tox -eshellcheck` over the current tree and, separately, report whether `tools/mermaid-lint.sh` as `54e8d08` landed it (`git show 54e8d08:tools/mermaid-lint.sh`) passes `shellcheck` -- write it to a file in your scratch directory, do not check it out over the tree. Do the same for `tools/shellcheck-wrap.sh` and `tools/flake8wrap.sh` as `5f3c80c` left them. Report in under 350 words. |
| 6b | low | sonnet | none | Style conformance, the judgment portion. Execute the brief under *Style conformance — judgment portion* in `PUSH-AUDIT.md` over the five diffs (`git diff $M^1..$M` for the four merges above, plus `16e6173^1..16e6173`), in place of its `git diff develop...HEAD`. The conventions are in `AGENTS.md`. Note before you start that there is **no new Python and no new Rust** in this range, so most bullets will have no material -- say "no material" for each such bullet rather than inventing one. What there is: shell (`tools/mermaid-lint.sh` new in `54e8d08`; `tools/shellcheck-wrap.sh` and `tools/flake8wrap.sh` edited in `5f3c80c`), YAML (`.github/workflows/mermaid-lint.yml` new, `.github/workflows/pr-re-review.yml` edited, `.github/actionlint.yaml`), TOML (`.vscode/review-scope.toml` new in `ade2788`) and markdown. Judge the shell against the repository's existing scripts in `tools/`, and the workflows against the other files in `.github/workflows/`. One specific question: `5f3c80c` edited two wrapper scripts while deleting the tool one of them referenced -- is what remains coherent, or does either script still carry a vestige of the deleted automation? Report in under 300 words. |
| 6c | medium | sonnet | none | Wave 2 mechanical, plus 2a code quality. Run `AUDIT_RANGE="$M^1..$M" tools/audit/wave2-mechanical.sh` once for each of the four merges and report its output; it never exits non-zero on findings. Then execute the *2a. Code quality* brief in `PUSH-AUDIT.md` over the five diffs, with that output as input. Of 2a's four shared blocks, be honest about which bind: `python-version-discipline` and `source-file-size` have no material (no Python, and the largest file added is `tools/mermaid-lint.sh` at 124 lines as landed); `comment-proportion` does bind, and `tools/mermaid-lint.sh` is the file to apply it to -- it is heavily commented by design because it is a copy of a template, so judge whether the comments explain *why* rather than *what*, and say if the proportion is defensible. `plan-references-in-code` binds and has real material: grep the five diffs for "phase <number>" and for plan filenames in anything that is not under `docs/plans/`, and in particular check `.claude/CLAUDE.md`, `docs/development.md`, `docs/testing.md` and the two workflows. Cross-phase questions (decision 1): `.claude/CLAUDE.md` was edited by both `5f3c80c` (removing an addresser row) and `54e8d08` (adding a mermaid row) -- is the result internally consistent? `PUSH-AUDIT.md` was edited by both `cbca9b1` and `54e8d08`; are the four blocks correctly ordered and separated, with no duplicated or orphaned marker? Report blocking or advisory per finding, with file and line, in under 400 words. |
| 6d | medium | sonnet | none | 2b test review over the five diffs. Execute the *2b. Test review* brief in `PUSH-AUDIT.md`; its `functional-test-coverage` shared block binds. This range is unusual and the brief should be read with that in mind: it adds no tests, and it **deletes** one (`kerbside/tests/unit/test_render_review.py`, 5f3c80c). Answer three questions directly. (1) Was that deletion correct -- did `test_render_review.py` test anything other than `tools/render-review.py`, which the same merge deleted? Read it with `git show 5f3c80c^1:kerbside/tests/unit/test_render_review.py`. Confirm `tox -epy3` passes on the current tree and report the test count. (2) `54e8d08` added executable shell (`tools/mermaid-lint.sh`) and a workflow, with no test of either. Apply the `functional-test-coverage` block: is that a gap, or is the lane its own test because it runs over the whole corpus on every markdown change? State which, and why. Check specifically whether the lane as `54e8d08` landed it would have run on a change to the script itself -- read the `paths:` filters in `git show 54e8d08:.github/workflows/mermaid-lint.yml` -- and compare with the filters on `develop` today. (3) `ade2788` added `.vscode/review-scope.toml`, which `./tools/review-tracking.sh scope-orphans` reads. Does anything fail if that file becomes malformed or drifts from the tree? Run `./tools/review-tracking.sh scope-orphans` and report its exit status. Do not mutate the tree; if you need to test a malformed copy, work on a copy in your scratch directory. Report in under 400 words. |
| 6e | medium | opus | none | 2c documentation review over all five diffs, including the plan-only `16e6173`. Execute the *2c. Documentation review* brief in `PUSH-AUDIT.md`. Four shared blocks bind: `readme-discipline`, `llm-doc-discipline`, `diagram-discipline` and `plan-phase-references`. This is the largest body of material in the range. Hold these together: `docs/development.md` (the review session recipe, `ade2788`), `docs/testing.md` (the mermaid lane, `54e8d08`), `.claude/CLAUDE.md` (edited twice), `PUSH-AUDIT.md` and `PLAN-TEMPLATE.md` (the five shared blocks), `AGENTS.md`, `ARCHITECTURE.md` and `README.md`. The first question is cross-phase: does any page still state something a later phase overturned? Check at least these -- does anything still describe the comment addresser, `pr-address-comments.yml`, `render-review.py` or `review-schema.json` as live (`5f3c80c` deleted them)? Does `docs/development.md`'s review recipe still match what `./tools/review-tracking.sh` actually offers, and do the commands in it run and produce file paths? Does `docs/testing.md`'s description of the mermaid lane match the workflow on `develop` today, given that `c053cc3` later added a fork guard and `45af922` moved the runner label from `debian-12-docker` to `debian-13-docker`? Second, verify every shared block in `PUSH-AUDIT.md` and `PLAN-TEMPLATE.md` is byte-identical to its canonical copy in `shakenfist/development` at `origin/main` under `templates/shared-blocks/`, including the version number in the opening marker, using `diff` and not by eye -- the master plan's review checklist requires this and `/srv/kasm_profiles/mikal/vscode/src/shakenfist/development` is a current checkout. Third, apply `plan-phase-references`: grep `README.md`, `AGENTS.md`, `ARCHITECTURE.md` and `docs/` outside `docs/plans/` for "phase <number>" and for named people. Fourth, check every *Future work* entry in the five phase plans and in the master plan for an issue or somewhere live that still tracks it, reading GitHub only with `gh issue view`, `gh issue list` and `gh pr view`; note that the master plan's *Future work* names two `check_github_security()` defects and one `review-coverage` signing gap that were to be filed against `shakenfist/development` -- say for each whether an issue now exists. Report blocking or advisory per finding, with file and line, in under 550 words. |
| 6f | high | opus | none | 2d security review over the five diffs. Execute the *2d. Security review* brief in `PUSH-AUDIT.md`; its `path-traversal-review` block binds. There are two large, opposite changes to CI privilege here and both need a verdict. (1) `5f3c80c` **deleted** `.github/workflows/pr-address-comments.yml`, which held `contents: write` on the pull request branch. Confirm from `git show 5f3c80c^1:.github/workflows/pr-address-comments.yml` what it could do, and confirm nothing else in the tree still grants that: grep every file in `.github/workflows/` on `develop` for `contents: write` and report each hit with a judgement on whether it is justified. Also confirm the deletion left no dangling caller -- `git show 5f3c80c` edited `pr-re-review.yml` and `tools/shellcheck-wrap.sh`; does any workflow, script or doc still invoke a deleted path? (2) `54e8d08` **added** `.github/workflows/mermaid-lint.yml`, which runs the checkout's own `tools/mermaid-lint.sh` on a self-hosted VM runner, outside the container that `--network none` and the read-only mount constrain. Survey finding 5 says this was a real fork-pull-request exposure, filed as `shakenfist/development`#323 and fixed here by `c053cc3` on 2026-10-25. Do not re-fix it (decision 5); confirm three things instead. Was the exposure genuinely present as `54e8d08` landed it -- read `git show 54e8d08:.github/workflows/mermaid-lint.yml` and say what a fork pull request editing the script could have reached. Does the workflow on `develop` today fully close it -- check the `head.repo.full_name` guard, whether `persist-credentials` is now false, and whether `workflow_dispatch` or `push` leaves another route in. And does anything else in the five diffs have the same shape, i.e. runs repository-controlled content on a self-hosted runner with credentials? Then the floor checklist's item 3: did any of the five diffs put a secret, a token, a private hostname, an address outside loopback and the documentation ranges, a username or a home or scratchpad path into this public repository? The weAudit sidecars (`.vscode/mikal.weaudit`, `.vscode/mikal.weaudit-shas.json`, edited by `5f3c80c`), `REVIEWS.md` and `.vscode/review-scope.toml` are prose and paths written by a human and are the likeliest place for one -- read them in the diff. Item 2: the mermaid lane runs unattended on `push` to `develop`; does its failure reach a human, or is it only visible on the Actions tab? Say which, and whether that is acceptable for an advisory lane. Item 5: does anything in the range publish an artefact? Report severity, file, line, class and fix per finding, in under 550 words. |
| 6g | medium | sonnet | none | Review phase 3's upstream landing under its own repository's runbook (decision 3). The commit is `223373f9d61e838242a17a447c08003c5ff5879a` in `shakenfist/development`, PR #73, merged 2026-08-31; a current checkout is at `/srv/kasm_profiles/mikal/vscode/src/shakenfist/development`. First confirm the premise: search that repository's `docs/plans/` and the bodies of its merged pull requests around that date with `gh pr view` for any push audit whose range includes `223373f`. If one exists, report it and stop -- the block says cite rather than re-run. Otherwise read `git -C ../development show 223373f` and execute that repository's own `PUSH-AUDIT.md` judgment briefs -- style, 2a, 2b, 2c, 2d -- over that one diff. Do not run its wave 1 scripts against a worktree unless they are cheap and self-contained; if you do, use `git -C ../development worktree add --detach` under your scratch directory and remove it afterwards. Weight 2b heaviest: the change widens an audit check, and a widened check that passes a repository running no linter at all is worse than the false negative it fixed. The new route is `SKILLSAW_RUN_RE = re.compile(r'^\s*skillsaw\b')` in `scripts/audit-check.py`. Answer directly: does the anchor match an install line such as `uv pip install skillsaw==0.18.0`, or a wrapped continuation of one, or a mention inside a comment? Does `scripts/test_audit_check.py` contain a test asserting that an install with no invocation still fails, and does that test actually fail if the anchor is removed -- mutate a copy in your scratch directory and run that repository's test suite to find out. Report severity, file and fix per finding, say for each whether it is still present at `development`'s `origin/main` today, and state plainly that findings here are to be filed against `shakenfist/development` rather than fixed in kerbside. Report in under 450 words. |
| 6h | high | (management session) | n/a | Triage and record. Take 6a to 6g's reports. Reproduce every finding against the tree before accepting it -- a sub-agent's summary describes what it intended, not necessarily what it found. Classify each as blocking or advisory, and decide for each: fix in the follow-up pull request, decline with the reason in writing, or file as an issue (showing Mikal the wording before filing). Give a verdict on each of the five floor-checklist items in `PLAN-TEMPLATE.md`'s `plan-push-audit-phase` block, for kerbside and for the upstream landing. Write it all into this plan's *Outcome* section. Then close the plan out per decision 6: mark phase 6 `Complete` in the master plan's Execution table with no `Merged` cell, update `docs/plans/index.md`, and apply decision 4's rewording to the master plan's `.sfui-commit` success criterion. Set the plan's own status to `Complete` only if every finding is resolved or declined, noting in the index row that `review-coverage` is still failing by master plan decision 5. Commit subject: "Record the consistency audit push audit." |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| The audit passes vacuously because a range resolved to nothing. `PUSH-AUDIT.md` names this as the failure mode of a merged branch. | 6a reports the exit code of every run and is told that exit 6 is a stop condition. 6a must also state, per merge, whether the Python gates had any material -- which turns a silent vacuous pass into an explicit "no material", the one answer a reader can check. Decision 1's per-merge ranges are each provably non-empty: the diffstats are in *Audit range*. |
| A step widens a range or re-vendors sfui to make a check green. | Both are named as prohibited in the briefs that could do them (6a, and decision 4 for sfui). 6h reproduces every finding before accepting it. |
| The security review spends its effort re-deriving the mermaid finding the survey already found, and misses the rest of the range. | 6f's brief gives it the finding, its upstream issue number and its fix commit, and asks three narrow confirmation questions instead. Its remaining budget is directed at the `contents: write` deletion and the floor items. |
| Phase 5's defect being already fixed makes the whole audit look like a formality. | It is the opposite, and 6h records it as such: the audit phase runs seven weeks after the code landed, and an exposure on a self-hosted runner was caught by an unrelated template re-sync rather than by this plan. That is a finding about the plan's own shape, and it belongs in *Outcome* where the next master plan's author will read it. |
| 6e's byte-for-byte block comparison drifts because the canonical copies moved after this plan adopted them. | Expected, and the point: `plan-push-audit-phase` is already at v4 where phase 1 adopted an earlier version. 6e reports the version numbers it found on both sides, so a stale block is a recorded finding rather than a surprise. Updating blocks is follow-up work, not this phase's. |
| The follow-up pull request never happens and the findings sit in the plan. | Decision 6 keeps the plan `In progress` until every finding is fixed or declined in writing. A declined finding must say why, in *Outcome*. |

## Definition of done

Every item is checkable against the branch or against a named
command's output.

- [ ] `PUSH-AUDIT.md`'s wave 1 has been run once per merge for
      `cbca9b1`, `5f3c80c`, `ade2788` and `54e8d08`, with
      `AUDIT_RANGE` set per decision 1, and every exit code is
      recorded in *Outcome*. No run exited 6.
- [ ] For each of those four merges, *Outcome* states whether
      `tox -eflake8` and `tox -epy3` had any material from it.
- [ ] `tox -eshellcheck` passes on the current tree, and
      *Outcome* records whether `tools/mermaid-lint.sh` as
      `54e8d08` landed it passes `shellcheck`.
- [ ] `tools/audit/wave2-mechanical.sh` has been run once per
      merge and its output recorded.
- [ ] All five judgment briefs in `PUSH-AUDIT.md` -- style,
      2a, 2b, 2c, 2d -- have been executed over the union of
      the five diffs, and each shared block that binds is
      named in *Outcome* with its verdict. A block with no
      material says "no material" rather than being omitted.
- [ ] Every shared block in `PUSH-AUDIT.md` and
      `PLAN-TEMPLATE.md` has been diffed against its canonical
      copy in `shakenfist/development` at `origin/main`, and
      *Outcome* records the version number found on each side.
- [ ] Each of the five floor-checklist items in
      `plan-push-audit-phase` has a verdict, or a sentence
      saying why it does not apply, for kerbside and for the
      upstream landing.
- [ ] Phase 3's upstream landing has either a cited audit or
      the review from step 6g, and *Outcome* says which.
- [ ] *Outcome* records the phase 5 fork-pull-request exposure
      as a confirmed finding, with the commit that introduced
      it (`54e8d08`), the commit that fixed it (`c053cc3`),
      and a statement of whether it is closed on `develop`
      today.
- [ ] Every finding is classified blocking or advisory and
      has a disposition: fixed in the follow-up pull request,
      declined with a written reason, or filed as an issue
      with its number.
- [ ] The master plan's Execution table marks phase 6
      `Complete` with an empty `Merged` cell, and
      `docs/plans/index.md` agrees with it.
- [ ] The master plan's `.sfui-commit` success criterion
      reads as decision 4 describes, and the index row says
      `review-coverage` is still failing by decision 5.
- [ ] The four master-plan corrections from the survey
      (findings 1, 2, 3 and 7) are present in
      `PLAN-consistency-audit.md` and `docs/plans/index.md`.
- [ ] `pre-commit run --all-files` is clean.

## Outcome

To be written by step 6h. Expected subsections: *Wave
results*, *Floor checklist: kerbside*, *Floor checklist:
upstream landing*, *To fix in the follow-up pull request*,
*Filed*, and *Declined, and why*.

## Future work

To be written by step 6h, if the audit raises anything that
is neither fixed nor declined. The master plan's own *Future
work* section already carries three upstream items that 6e
checks for issues.

## Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the
work you intend to do aligns with that plan.

There is one gate in this phase. Steps 6a to 6g only read and
report, so they need no approval beyond the plan. Step 6h
both records the outcome and closes the plan out, and two of
its actions are expensive to undo: rewording the master
plan's sfui success criterion (decision 4) and setting the
plan's status to `Complete`. Bring the proposed wording of
both to the management session, and to Mikal, before
committing them -- decision 4 is the one most likely to be
argued with, and the alternative it names (a one-line
re-vendor in the follow-up pull request instead) is still
available at that point.
