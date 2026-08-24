# Title for the plan

## Prompt

Before responding to questions or discussion points in this
document, explore the kerbside codebase thoroughly. Read
relevant source files, understand existing patterns (the
Rust SPICE proxy in `rust/kerbside-proxy/` and the gRPC
control contract in `kerbside/rpc/`, the source driver
abstraction in `kerbside/sources/`, the REST API in
`kerbside/api.py`, the SQLAlchemy/alembic data model in
`kerbside/db.py` and `kerbside/migrations/`, Pydantic-based
config in `kerbside/config.py`, audit logging, and the .vv file
generation path). Ground your answers in what the code
actually does today. Do not speculate about the codebase
when you could read it instead. Where a question touches on
external concepts (SPICE protocol, QXL, vdagent, libvirt
graphics, OpenStack Nova consoles, oVirt console API,
Shaken Fist), research as needed to give a confident
answer. Flag any uncertainty explicitly rather than
guessing.

Consult `ARCHITECTURE.md` for the overall proxy
architecture, channel model, and connection lifecycle.
Consult `AGENTS.md` for build commands, project
conventions, key file map, and code organisation. The
`docs/` tree contains protocol documentation derived from
upstream SPICE sources and verified against this
implementation — `protocol-overview.md`,
`channel-protocols.md`, `compression-protocols.md`,
`spice-link-protocol.md`, `vd-agent-protocol.md`,
`scancodes.md`, `usb-redirection.md`,
`console-sources.md`, `proxy-architecture.md`, and
`capabilities.md`. Key cross-repo references:

- `shakenfist/ryll` — the Rust SPICE client; the headless
  mode and (eventually) its control socket are the
  primary automated test driver
- `shakenfist/uncalibrated-sextant` — UEFI Rust test
  target guest with on-screen QR digest and serial event
  drain; the assertion oracle for automated SPICE tests
- `shakenfist/kerbside-patches` — patches applied to
  upstream components (Nova, libvirt, etc.) for full
  Kerbside integration; relevant when changes touch the
  hypervisor-facing contract
- `shakenfist/shakenfist` — the Shaken Fist cloud, one of
  the supported source hypervisors
- External: the SPICE protocol sources at
  `gitlab.freedesktop.org/spice/spice-protocol` and the
  reference C client at `spice-gtk`

<!-- shared-block: plan-file-conventions v1 -->
Plan file conventions (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-file-conventions.md`):

- All planning documents live in `docs/plans/`.
- Detailed planning gets one plan file per phase. Phase files are
  named for their master plan, sit in the same directory as it,
  and append `-phase-NN-descriptive` before the `.md` extension.
- The master plan tracks its phases in a table under its Execution
  section:

  | Phase | Plan | Status |
  |-------|------|--------|
  | 1. Schema migration | PLAN-thing-phase-01-schema.md | Not started |
  | 2. Public API | PLAN-thing-phase-02-api.md | Not started |

- One commit per logical change, and at minimum one commit per
  phase. Unrelated changes are not batched into a single commit.
  Each commit is self-contained: it builds, passes tests, and has
  a message explaining what changed and why.
<!-- shared-block-end -->

## Situation

...

## Mission and problem statement

...

## Open questions

...

## Execution

...

### Phase status

<!-- shared-block: plan-status-vocabulary v1 -->
Plan status vocabulary (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-status-vocabulary.md`):

A status cell -- in the master plan's own Execution phase table, and
in the row `docs/plans/index.md` carries for the plan -- holds
exactly one of these terms and nothing else:

- `Proposed` -- written down as a concept, not yet scheduled.
- `Not started` -- scheduled, but no work has begun.
- `In progress` -- work has begun and has not finished.
- `Blocked` -- cannot proceed until something outside the plan
  changes. Say what, in the plan.
- `Complete` -- the work is done.
- `Abandoned` -- deliberately dropped without being done.
- `Superseded` -- replaced by another plan, which the plan names.

The term is the whole cell. No dates, no phase arithmetic, no
parenthetical qualifiers, no summary of what happened: a status is
read to decide whether a plan still wants attention, and prose in
that column has repeatedly grown until it could no longer be read
either by a person scanning the table or by tooling. Detail belongs
in the plan file, and a one-line summary belongs in the index's own
Intent column.

Matching is case-insensitive, so `In Progress` is accepted, but the
spelling above is the one to write.
<!-- shared-block-end -->

The last row of every master plan's phase table is a push audit:
work through [`PUSH-AUDIT.md`](PUSH-AUDIT.md) over the plan's
**accumulated** diff — every phase together, against `develop` —
rather than over the final phase alone, because what the phases did
to each other is only visible once they are in the same diff. Name
the commit range explicitly in the phase, and substitute it wherever
`PUSH-AUDIT.md` says `git diff develop...HEAD`; once earlier phases
have merged, that range is empty on the audit branch. Findings land
as their own pull request, and the plan is not complete until each
one is fixed or declined in writing in the plan, with the reason. An
audit that finds nothing is recorded in a sentence — it is a result
worth having.

## Agent guidance

### Execution model

<!-- shared-block: subagent-execution-model v1 -->
Sub-agent execution model (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/subagent-execution-model.md`):

All implementation work is done by sub-agents, never in the
management session. The management session is reserved for
planning, review, and decision-making. This keeps the management
context lean and avoids drowning it in implementation diffs.

The workflow is:

1. **Plan** at high effort in the management session.
2. **Spawn a sub-agent** for each implementation step with the
   brief from the plan, at the recommended effort level and model.
3. **Review** the sub-agent's output in the management session.
   Check the actual files -- the sub-agent's summary describes
   what it intended, not necessarily what it did.
4. **Fix or retry** if the output is wrong. Diagnose whether the
   brief was insufficient (improve it) or the model was too light
   (upgrade it), then re-run.
5. **Commit** once the management session is satisfied.

This applies to all steps, including high-effort ones. If a
sub-agent cannot succeed even with a detailed brief and the right
model, that is a signal the brief needs improving, not that the
management session should do the implementation itself.

Use `isolation: "worktree"` for sub-agents when the change is
risky or experimental; the worktree is discarded if the output is
unsatisfactory. For safe, well-understood changes, sub-agents can
work directly in the main tree.
<!-- shared-block-end -->

### Planning effort

<!-- shared-block: plan-planning-effort v1 -->
Planning effort (shared block; do not edit -- the canonical copy
lives in shakenfist/development at
`templates/shared-blocks/plan-planning-effort.md`):

The master plan itself is always created at **high effort** -- it
requires broad codebase understanding, cross-referencing several
source files, and judgment calls about scope and sequencing.

Each phase plan states the recommended effort level for planning
that phase. Phases that turn on design decisions, cross-component
coordination, protocol changes, or subtle correctness questions
should be planned at high effort. Phases that are mechanical, or
that follow a pattern already established elsewhere in the
codebase, can be planned at medium effort.
<!-- shared-block-end -->

!!! note "In this project"

    Phases involving deep protocol research (SPICE channel
    semantics, vdagent behaviour, hypervisor console quirks),
    database schema changes, or architectural decisions should
    be planned at high effort. Phases that are mechanical or
    follow well-established patterns can be planned at medium
    effort.

### Step-level guidance

<!-- shared-block: subagent-step-guidance v1 -->
Sub-agent step guidance (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/subagent-step-guidance.md`):

Each phase plan includes a table like this:

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | medium | sonnet | none | One-sentence summary of what to do and which files to touch |
| 1b | high | opus | worktree | Why this needs high effort: requires understanding X to do Y |

**Effort levels**, from cheapest to most thorough:

- **low** -- Purely mechanical changes: rename, reformat, add a
  log line, regenerate generated code. The brief is a complete
  instruction.
- **medium** -- The plan provides enough context to follow a clear
  brief. The sub-agent may read a few files, but the approach is
  already decided.
- **high** -- Requires reading several files, making judgment
  calls, or understanding non-obvious invariants. The sub-agent
  needs to think about edge cases.
- **xhigh** -- The setting for hard coding and agentic steps:
  long-horizon changes, or steps where the sub-agent must both
  research and implement.
- **max** -- Correctness matters more than cost. Expect
  diminishing returns and occasional overthinking; reserve it for
  steps where a wrong answer would be expensive to detect.

**Brief for sub-agent:** this is the key field. Write it as if
briefing a colleague who has never seen the codebase. Include what
to change, which files to touch, what patterns to follow, and any
non-obvious constraints.

A good brief front-loads the research the planner already did, so
the implementing agent does not repeat it. Instead of "add storage
functions for the new object", name the functions to add, the file
they belong in, the existing equivalent to mirror (with line
numbers), and any registration the change also needs.

The better the brief, the lower the effort level needed and the
lighter the model that can succeed.
<!-- shared-block-end -->

!!! note "In this project"

    The non-obvious invariants that push a step to high effort
    are SPICE channel ordering, capability negotiation, ticket
    and token lifecycle, DB migration safety, and audit log
    guarantees.

    A worked brief for this codebase: instead of "add an
    endpoint for X", write "add a new endpoint `POST /api/v1/X`
    in `kerbside/api.py` alongside the existing `POST
    /api/v1/consoles` handler at line ~210. Use the same
    `pydantic` request-model pattern, the same auth decorator
    (`@requires_auth`), and persist via the `Source` model in
    `kerbside/db.py`. Add an audit event of type `X_CREATED`
    matching the convention at line ~340."

### Model choice

<!-- shared-block: subagent-model-roster v1 -->
Sub-agent model roster (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/subagent-model-roster.md`):

The planner recommends which model is best suited to each step.
This is a judgment call, not a rigid rule -- the right model
depends on what the step requires, not on whether it is "planning"
or "implementation". The models available to sub-agents are:

- **fable** -- The most capable model available, for the hardest
  reasoning and the longest-horizon work: multi-step changes a
  single sub-agent must carry end to end, or steps whose
  correctness depends on holding a whole subsystem in mind at
  once. It costs materially more than opus, so reserve it for
  steps that have already defeated opus or are expected to.
- **opus** -- The default for steps needing deep reasoning,
  architectural understanding, subtle correctness judgment
  (locking, state machines, migrations), or intricate
  implementation that would be costly to debug if it were wrong.
- **sonnet** -- A good default for well-briefed implementation
  work. Faster and cheaper than opus, and effective when the plan
  front-loads the research and the brief leaves no broad judgment
  calls to make.
- **haiku** -- Suitable for purely mechanical tasks:
  search-and-replace, regenerating generated code, adding log
  lines, running commands. The brief must be a near-complete
  instruction.

Model choice interacts with effort level and brief quality. A
detailed brief compensates for a lighter model -- sonnet at medium
effort with a thorough brief often matches opus at medium effort
with a vague brief. The planner's job is to write briefs good
enough that the recommended model can succeed.

The model also determines the context window: fable, opus and
sonnet have 1M tokens, haiku has 200K. A step that must hold many
files in context at once may need one of the larger-context models
for that reason alone, even when the reasoning itself is
straightforward.

**When in doubt, skew to the more capable model.** Saving money
only matters if the outcome is still acceptable. A failed or
low-quality implementation wastes more time -- and therefore more
money -- than the heavier model would have cost. Recommend a
lighter model only when you are confident the brief is detailed
enough for it to succeed.
<!-- shared-block-end -->

### Management session review checklist

<!-- shared-block: plan-review-checklist v1 -->
Management session review checklist (shared block; do not edit --
the canonical copy lives in shakenfist/development at
`templates/shared-blocks/plan-review-checklist.md`):

After a sub-agent completes, the management session verifies:

- [ ] The files that were supposed to change actually changed --
      read them, do not trust the summary.
- [ ] No unrelated files were modified.
- [ ] The changes match the intent of the brief: not merely
      syntactically correct, but semantically right.
- [ ] The project's own pre-merge checks pass, including any
      generated code that has to be regenerated and committed
      (see the project-specific checks below).
- [ ] The commit message follows project conventions, including
      the `Co-Authored-By` line recording model, context window,
      and effort level.
<!-- shared-block-end -->

!!! note "In this project"

    The project-specific checks referred to above are:

    - [ ] The code passes `tox -eflake8` and `tox -epy3`.
    - [ ] If a DB migration was added, the alembic upgrade and
          downgrade paths were both exercised.

## Administration and logistics

### Success criteria

We will know when this plan has been successfully
implemented because the following statements will be true:

* The code passes `tox -eflake8` and `tox -epy3`.
* Coverage from `tox -ecover` does not regress
  meaningfully for touched modules.
* New code follows existing patterns: pydantic config,
  SQLAlchemy session usage, the audit logging convention,
  the existing `kerbside/sources/base.py::BaseSource`
  interface for new source backends, and the Rust proxy's
  SPICE handling in `rust/kerbside-proxy/`.
* There are unit tests for new logic, and the existing
  tests still pass. Integration coverage in the tempest
  plugin has been extended where the change is
  user-visible.
* Lines are wrapped at 120 characters; Python strings use
  single quotes except for docstrings (which use double
  quotes); trailing whitespace is removed.
* `README.md`, `ARCHITECTURE.md`, and `AGENTS.md` have
  been updated if the change adds or modifies endpoints,
  hypervisor backends, configuration knobs, DB schema,
  or the SPICE proxy contract.
* Documentation in `docs/` has been updated to describe
  any new features or configuration options. If protocol
  documentation in `docs/channel-protocols.md`,
  `docs/spice-link-protocol.md`, or related files is
  affected, it has been updated and cross-checked against
  the implementation.
* If the changes affect the hypervisor-facing contract,
  the relevant patches in `shakenfist/kerbside-patches`
  have been reviewed and updated if needed.
* The `PUSH-AUDIT.md` audit has been run over the plan's
  accumulated diff, and every finding it raised has been
  fixed or declined in writing in the plan.

### Documentation index maintenance

When creating a new master plan from this template,
update the following file in `docs/plans/`:

* **`index.md`** — add a row to the *Master plans* table
  with the creation date, a link to the plan, a one-line
  intent summary, the initial status, and links to each
  phase plan file. Keep the table in chronological
  order.

When all phases of a plan are complete, update the
status column in `index.md` to *Complete*.

<!-- shared-block: plan-closeout-sections v1 -->
Plan close-out sections (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/plan-closeout-sections.md`):

### Future work

We should list obvious extensions, known issues, unrelated bugs we
encountered, and anything else we should one day do but have
chosen to defer to here, so that we do not forget them.

...

### Bugs fixed during this work

This section should list any bugs we encounter during development
that we fixed. You should also scan the project's issue tracker,
where one exists, for directly related issues that we should
either resolve as part of this master plan or at least be aware of
while planning it.

...

### Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work you
intend to do aligns with that plan.
<!-- shared-block-end -->
