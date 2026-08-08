# Two-tier CI phase 3: merge queue adoption and tier split

Phase 3 of [PLAN-two-tier-ci.md](PLAN-two-tier-ci.md). This is the
phase that actually delivers the "two tier" in two-tier CI: phases 1
and 2 only strengthened and grew the lanes that run on pull requests;
nothing has yet moved *out* of the PR tier, and nothing actually
*gates* a merge.

## Prompt

"What is the next step with this plan? We've **added** CI, but we
haven't actually implemented a two tier approach to CI yet."

## Situation

### What gates merges today: nothing

Kerbside's only branch protection is the "Protect default branch
history" ruleset (id 20252051): `deletion` and `non_fast_forward`.
There are **no required status checks and no merge queue** — the PR
rollup is purely advisory and the maintainer merges by hand when it
looks green. Phase 3 is therefore not "re-wire required checks"; it
introduces merge gating to this repository for the first time.

### What runs on PRs today

- `functional-tests.yml`: `sanity_checks` (lint + unit, m runner)
  → `ovirt_matrix` (l, ~2h) and `openstack_matrix` (m, hours) in
  parallel → `automated_reviewer` (needs all three). Review-only
  changes are skipped via trigger-level `paths-ignore` (PR #254).
- `direct-qemu-functional.yml`: `direct-qemu-lane` (l, ~1h), same
  `paths-ignore`.
- `sf-e2e-functional.yml`: `sf-e2e` (l, ~17–35m), same
  `paths-ignore` (phase 2).
- `rust.yml`: path-scoped to `rust/**` + the proto, so it only runs
  when Rust is touched.
- `codeql-analysis.yml`, `pin-indirect-dependencies.yml`: advisory.

The slow feedback problem is the two cloud matrices: every PR pays
for a full oVirt and a full OpenStack deployment.

### The fleet precedent (grounded 2026-08-09)

shakenfist/shakenfist has run exactly this design in production
since 2024, and client-python-k3s adopted the same shape
(`docs/plans/functional-ci.md` there is the conversion recipe for a
smaller repo). The pattern:

- **One workflow file**, both `pull_request` and `merge_group`
  triggers, tiers separated by `if: github.event_name` job gating —
  not separate workflow files. Aggregation requires this: the gate
  jobs `needs:` the tier jobs, and `needs:` cannot cross workflows.
- **Three aggregate gate jobs**, whose display names are the only
  lane-related required status checks:
  - `can_see_status` ("Can see status"): runs `true`
    unconditionally on every event. Its job is to guarantee the
    workflow always reports *something*, so a required check can
    never sit in "Expected — waiting for status" forever.
  - `can_enqueue` ("Can enqueue"): `if: always() &&
    github.event_name != 'merge_group'`; needs the smoke-tier jobs;
    passes iff every need ended `success` or `skipped` (a jq
    expression over `toJSON(needs)`).
  - `can_merge` ("Can merge"): `if: always() && github.event_name
    == 'merge_group'`; needs the merge-tier jobs; same jq.
  On a PR, "Can merge" reports `skipped`, which **satisfies** a
  required check; in a merge group, "Can enqueue" reports `skipped`
  likewise. That skipped-satisfies property is what lets one
  required-check list serve both refs.
- **A `check_paths` job replaces trigger-level `paths-ignore`**
  (dorny/paths-filter@v4 with `predicate-quantifier: 'every'`,
  output defaulting to `code_changed=true` on `workflow_dispatch`).
  This is load-bearing, not style: a required check belonging to a
  `paths-ignore`'d workflow never reports on a filtered PR, and a
  required check that never reports blocks the merge forever. With
  `check_paths`, the workflow always runs; heavy jobs skip on the
  filter output and the skip satisfies the requirement.
- **The ruleset** (shakenfist/shakenfist "Develop branch",
  id 2681531): `deletion`, `non_fast_forward`, `pull_request`
  (0 required approvals), `merge_queue` (merge_method `MERGE`,
  grouping `ALLGREEN`, `max_entries_to_build` 1,
  `min_entries_to_merge` 1, `max_entries_to_merge` 5,
  `min_entries_to_merge_wait_minutes` 5,
  `check_response_timeout_minutes` 360), and
  `required_status_checks` = the three gate names, integration
  15368 (the GitHub Actions app — the gates are ordinary Actions
  jobs, not an external app).
- **The conductor needs no changes.** private-ci provisions runners
  from queued jobs by label, and merge-group jobs request the same
  labels as PR jobs. Kerbside is not special-cased there today and
  does not become so.

## Design decisions

1. **Single workflow file, event-gated tiers.** The master plan
   sketched "move ovirt_matrix and openstack_matrix out of
   functional-tests.yml into a merge-tier workflow"; that sketch
   predates studying the fleet and is superseded. Keeping one file
   is what makes the gate jobs possible (`needs:` is same-file
   only), matches shakenfist/shakenfist and client-python-k3s, and
   keeps the pr-retest bot's `gh workflow run functional-tests.yml`
   working unchanged.
2. **Tier assignment.**
   - Smoke tier (every PR): `sanity_checks`, `direct-qemu-lane`,
     `sf-e2e`, plus advisory rust/codeql as today.
   - Merge tier (`merge_group` + `workflow_dispatch`):
     `ovirt_matrix` and `openstack_matrix`. This resolves master
     plan open question 2: the oVirt lane joined the merge tier,
     which phase 1 made defensible by turning it into a genuine
     integration gate; the schedule-only demotion remains the
     escape hatch if its flake rate ever dominates.
   - `sanity_checks` runs in **both** tiers: it is minutes on an m
     runner, the matrices already `needs:` it (fail-fast ordering
     worth keeping in the queue), and it re-validates lint/units
     against the *merged* tree, which no smoke run saw.
3. **Gate `needs:` lists must name every job whose failure should
   block — including jobs other needs already depend on.** The jq
   treats `skipped` as satisfied (required for path-skips), so a
   failure that manifests downstream as a skip is invisible: if
   `sanity_checks` fails in a merge group, the matrices skip, and a
   `can_merge` that needed only the matrices would go green on a
   broken tree. `can_merge` therefore needs
   `[sanity_checks, ovirt_matrix, openstack_matrix, check_paths]`,
   and `can_enqueue` needs `[sanity_checks, check_paths]`.
4. **`check_paths` replaces `paths-ignore`** in
   `functional-tests.yml`, `direct-qemu-functional.yml`, and
   `sf-e2e-functional.yml`, filtering on the same four
   review-tracking paths PR #254 skipped (`REVIEWS.md`,
   `.vscode/*.weaudit`, `.vscode/*.weaudit-shas.json`,
   `.vscode/review-scope.toml`) — behaviour parity, expressed as an
   inverse filter with `predicate-quantifier: 'every'`. Review-only
   PRs then pass all required checks via skips and can merge
   through the queue.
5. **`direct-qemu-lane` and `sf-e2e` become required checks too.**
   Each workflow gains a `merge_group` trigger and its own
   `check_paths`; the heavy job runs only on `pull_request` (with
   code changes), so a merge group costs them nothing — the jobs
   report `skipped`, which satisfies the requirement. Without this,
   a red smoke lane would not stop a merge, and the smoke tier
   would still gate nothing.
6. **`rust.yml` stays advisory.** It is deliberately path-scoped to
   `rust/**`, so as a required check it would deadlock Python-only
   PRs, and un-scoping it wastes an xl runner per PR. Rust
   breakage still gates merges: the ovirt and openstack merge-tier
   lanes both build and install the PR's proxy wheel (that build is
   what caught the 2026-08-02 tonic break).
7. **`automated_reviewer` re-anchors to
   `needs: [sanity_checks]`.** This is the master plan's stated
   deliverable and the human payoff: the review posts after
   minutes, not after the slowest cloud lane. The shared workflow
   already guards itself to same-repo `pull_request` events, so it
   never fires in a merge group.
8. **`SF_HEAD_SHA` gains a fallback**:
   `${{ github.event.pull_request.head.sha || github.sha }}`. The
   current expression is empty outside `pull_request` events (it
   already is on dispatch today); the fleet standardises on
   `github.sha` for non-PR refs.
9. **Concurrency groups are already merge-queue-safe.** Every group
   in the repo keys on `${{ github.ref }}`, and each merge-group
   ref (`refs/heads/gh-readonly-queue/develop/pr-N-...`) is unique,
   so queue entries can never cancel each other or a PR run. The
   master plan's concurrency worry is resolved by inspection.
10. **Ruleset parameters are copied from shakenfist/shakenfist**
    (values above) rather than re-derived. Notably `ALLGREEN` with
    `max_entries_to_merge` 5 means a stack of queued renovate PRs
    shares **one** merge-tier run instead of serialising a cloud
    deployment per dependency bump — resolving master plan open
    question 3. Renovate has no automerge enabled in this repo
    (minor/patch are `automerge: false`), so queue entry remains a
    human act for now; if automerge is ever enabled, renovate
    merges become "merge when ready" and batch the same way.
    `check_response_timeout_minutes` 360 comfortably covers the
    2-hour oVirt lane.

## Execution

| Step | What | Status |
|------|------|--------|
| 1 | Restructure `functional-tests.yml`: `merge_group` trigger, `check_paths`, event-gate the matrices, gate jobs, reviewer re-anchor | Complete |
| 2 | `direct-qemu-functional.yml` + `sf-e2e-functional.yml`: `merge_group` trigger, `check_paths`, skip-in-queue | Complete |
| 3 | Documentation: falsified statements only (AGENTS.md CI sections, master plan cross-offs); the full docs pass stays phase 4 | Complete |
| 4 | Operator: apply the ruleset change (below), then dispatch `export-repo-config.yml` to archive it | Not started |
| 5 | Live validation: merge a scratch PR through the queue; watch the first real merge group end to end | Not started |

Rollout order matters and is safe: the workflow changes land first
and are inert without a queue (`merge_group` triggers never fire,
gate jobs run and report on PRs, nothing is required yet). The
ruleset flip is the activation step and is instantly revertible in
the UI, independent of any workflow revert.

### Step 4: the operator ruleset change (manual, GitHub UI or API)

Edit the existing "Protect default branch history" ruleset (or
create a "Develop branch" ruleset mirroring shakenfist/shakenfist
and retire the old one — preferred, for fleet-consistent naming).
Target: `~DEFAULT_BRANCH`. Rules:

- `deletion`, `non_fast_forward` (keep, as today)
- `pull_request`: 0 required approvals, dismiss stale reviews on
  push, all merge methods allowed
- `merge_queue`: merge_method `MERGE`, grouping `ALLGREEN`,
  max_entries_to_build 1, min_entries_to_merge 1,
  max_entries_to_merge 5, min_entries_to_merge_wait_minutes 5,
  check_response_timeout_minutes 360
- `required_status_checks` (all integration 15368 / GitHub
  Actions; strict policy off):
  - `Can see status`
  - `Can enqueue`
  - `Can merge`
  - `direct-qemu-lane`
  - `sf-e2e`

Then dispatch `export-repo-config.yml` so
`.github/exported-config/` archives the new ruleset.

### Step 5: validation plan

The gate jobs' PR-side behaviour is proven by this phase's own PR
(gates appear in the rollup; "Can merge" reports skipped). The
merge-group path cannot execute until the ruleset flips, so after
step 4: queue a trivial scratch PR, confirm entry requires the
required checks, confirm the merge group runs `sanity_checks` +
both matrices + `can_merge` and merges on green. `workflow_dispatch`
still runs the matrices directly for lane debugging, but note a
dispatch run never attaches checks to a PR — for a wedged PR
rollup, close/reopen remains the reliable retrigger. If the queue
itself wedges, eject via the UI and consult the failure with the
merge-ci-triage skill; the 360-minute check timeout bounds how long
a dead entry can block the queue.

## Risks considered

- **Skip-masking in the gates** — addressed by decision 3 (direct
  `needs:` on every blocking job).
- **Review-only PR deadlock under required checks** — addressed by
  decision 4; this is the sharpest edge of the whole design, since
  the failure mode is a PR that can never merge.
- **dorny/paths-filter behaviour on `merge_group` refs** — not
  re-derived here: the identical `check_paths` job has run in
  shakenfist/shakenfist across both events since 2024.
- **Runner supply for merge groups** — none needed beyond today:
  merge-tier jobs request the same labels PR runs already use, and
  the conductor is label-driven.
- **Bootstrap paradox** — this phase's PR merges *before* the
  queue exists, so its merge_group code paths first execute during
  step 5's scratch PR, not on this PR. Accepted; the PR-side paths
  are exercised on this PR.

## Acceptance criteria

- A pull request runs sanity, direct-qemu, sf-e2e (and rust when
  touched) but **no cloud matrices**; PR feedback time drops from
  ~2 hours to the slowest smoke lane.
- Merging requires the merge queue; a queue entry deploys oVirt
  and OpenStack against the merged tree and blocks on failure.
- A review-marks-only PR merges through the queue with every
  required check satisfied by skips.
- The automated reviewer posts after the smoke tier, not after the
  cloud lanes.
