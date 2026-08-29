Thanks for your work on this. I appreciate it. Some final
checks before I push.

## How to use this template

The pre-push audit splits into two waves:

**Wave 1 — mechanical.** Build verification, lint, test
suite, and the parts of style conformance that grep can
answer. Wrapped in a single shell script so it runs as
one tool approval. Always run wave 1 first; wave 2 is
only worth spending on if wave 1 passes.

**Wave 2 — judgment.** Code-quality, test-coverage,
documentation, and security review. Some of this is
mechanical (TODO/FIXME grep, raw print() scan, broad
except clauses) and is wrapped in a second script; the
rest needs sub-agents to read code and apply judgment.
The four judgment agents are independent and can be
spawned in parallel.

The management session reviews all findings, fixes any
issues, and confirms the push.

**Note:** Both scripts already exist, at
`tools/audit/wave1.sh` and
`tools/audit/wave2-mechanical.sh`. They were adapted from
`shakenfist/ryll/tools/audit/`, with the lint and test
gates moved from cargo to tox and the style greps made
Python-flavoured. Run them, do not re-derive them.

## Wave 1: Mechanical checks

Run the consolidated script (one approval):

```
tools/audit/wave1.sh
```

It performs (and exits non-zero on any failure):

- `tox -eflake8` (the project's lint gate, also run by CI)
- `tox -epy3` (the unit test suite via stestr)
- Mechanical style checks: no raw `print()` in non-test
  source (logging only), no bare `except:` clauses, no
  `except Exception:` without a re-raise or a logged
  message, advisory long-line check on Python files in
  the diff over `AUDIT_RANGE`, and an advisory check for
  trailing whitespace on touched lines

Exit codes:

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | all wave 1 checks passed             |
| 1    | flake8 failed                        |
| 2    | py3 test suite failed                |
| 3    | raw `print()` added in non-test code |
| 4    | bare `except:` added in source       |
| 5    | could not reach the repository root  |
| 6    | an explicitly-set `AUDIT_RANGE` does not resolve |

Codes 3 and 4 are the only fatal style checks, and both
inspect **only lines added** relative to `AUDIT_RANGE`
(`develop...HEAD` by default), so pre-existing intentional
prints — the config and logging bootstrap, the `kerbside`
CLI — do not trip them. A `print()` may still be added
deliberately if its file carries the marker comment
`audit-allow-print`. Every other style check is advisory
and does not change the exit code.

Because those checks are diff-based, a branch whose work
has already merged to `develop` gets an empty diff and a
vacuous pass. Both `tools/audit/wave1.sh` and
`tools/audit/wave2-mechanical.sh` hard-code that default;
both now also read `AUDIT_RANGE` and `AUDIT_PATHS` from
the environment, so auditing an accumulated range — as a
master plan's push-audit phase does — is exporting those
instead of editing either script.
`tools/audit/plan-range.sh` derives both from a plan's
merge commits:

```
eval "$(tools/audit/plan-range.sh <first-merge-sha> <last-merge-sha>)"
```

Give the merge SHAs oldest-first: reversed, the derived
range diffs backwards and the style checks pass on
reverted content. The script rejects that, along with a
SHA that is not on `develop` or has no first parent, an
empty derived path set, and a path carrying whitespace, a
glob metacharacter or a quoting character — each of which
would otherwise make the audit inspect the wrong content
and pass. An explicitly-set `AUDIT_RANGE` that does not
resolve is fatal for the same reason (wave 1 exit 6, wave
2 exit 1); the default range stays advisory.

If wave 1 fails, fix the cause and re-run before
spending on wave 2.

### Style conformance — judgment portion

The script covers what grep can prove. The remaining
style questions need a sub-agent to read code:

| Setting | Value  |
|---------|--------|
| Model   | sonnet |
| Effort  | low    |

**Brief for sub-agent (only if wave 1 passes):**

Check `git diff develop...HEAD` for adherence to project
conventions in `AGENTS.md`:

- SPICE protocol handling: lives in the Rust proxy
  (`rust/kerbside-proxy/`), with packet grammar from
  the ryll `shakenfist-spice-protocol` crate; Python
  code must not reimplement SPICE parsing — the daemon
  talks to the proxy only through the gRPC contract in
  `kerbside/rpc/kerbside.proto`.
- Source backends: new sources subclass
  `kerbside.sources.base.BaseSource` and respect the
  documented method contract; capability flags are
  declared, not implied.
- API endpoints: pydantic request / response models;
  consistent auth decorator usage; audit events emitted
  for state-changing operations using the existing
  helper, not ad-hoc DB inserts.
- DB access: SQLAlchemy session lifecycle matches the
  existing per-request / per-task pattern; no raw SQL
  without justification; migrations are alembic-managed
  with both upgrade and downgrade paths.
- Config: new knobs go through `kerbside/config.py`
  pydantic models with sensible defaults and inline
  documentation, not via `os.environ` reads scattered
  through the codebase.
- Logging: messages use the project logger (no `print`,
  no bare `logging.info` against the root logger);
  log levels are appropriate (errors are errors, not
  warnings); user-controlled values are not logged in a
  way that enables log injection.
- Field rename / unit-change discipline: did any field
  silently change units (e.g. seconds → ms) without a
  rename or doc update?

Report a short list of any violations found. If none,
say "Style checks passed."

## Wave 2: Deeper review

Only run wave 2 after wave 1 passes.

Start with the consolidated mechanical script (one
approval):

```
tools/audit/wave2-mechanical.sh
```

It reports (does not block; never exits non-zero on
findings):

- TODO / FIXME / HACK / XXX in changed source files.
- Newly added `# noqa` annotations and what they
  suppress.
- Count of new test functions vs Python files changed.
- Documentation files touched (warns if none — the diff
  may have merited doc updates).
- New broad `except Exception` blocks (raw list —
  review whether each re-raises or logs appropriately).
- New `assert` statements in non-test code (asserts
  are stripped under `python -O`; usually a bug
  outside tests).
- Any new dependencies added to `pyproject.toml` /
  `bindep.txt` — surface for security review.
- New alembic revisions added — surface for migration
  review.

Then spawn the judgment agents below. They can run in
parallel.

### 2a. Code quality

| Setting | Value  |
|---------|--------|
| Model   | sonnet |
| Effort  | medium |

**Brief for sub-agent:**

The mechanical script
(`tools/audit/wave2-mechanical.sh`) already extracted
TODO/FIXME comments, broad excepts, asserts, and new
dependencies. Take that report as input.

Add the judgment-level review on the diff
(`git diff develop...HEAD`):

- **Duplicated code:** Are there significant blocks of
  duplicated logic that the mechanical scan can't see?
  Look for copy-paste patterns across hypervisor
  backends, packet parsers, or API endpoints.
- **Missed abstractions:** Should any new code be
  extracted into a shared module? Look for logic a
  second hypervisor backend or a second channel handler
  would likely need.
- **DB / connection lifecycle:** Are session scopes
  correct? Is there any path that opens a connection or
  acquires a lock without releasing it on the error
  path? Are SPICE channels closed cleanly on every exit
  path?
- **Triage the script's raw findings:** for each TODO /
  broad except / assert the mechanical script flagged,
  say blocking or advisory and why. Skip ones in test
  modules where they are appropriate.

<!-- shared-block: comment-proportion v1 -->
Comment proportion (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/comment-proportion.md`):

- A comment or docstring earns its length by saying what the code
  cannot: the contract, the units, the failure modes, the reason a
  surprising choice is correct. Restating the code in prose is not
  documentation.
- Treat as candidates any added comment or docstring that is longer
  than the code it documents, and any comment block over roughly
  fifteen lines attached to a body under ten. These are candidates,
  not verdicts -- a subtle algorithm, a public API contract, or a
  hard-won bug explanation can justify the length.
- Where the length is not justified the finding is advisory, and
  the fix is to cut the restatement rather than delete the comment:
  keep the why, drop the line-by-line narration of the what.
- Prose that documents user-visible behaviour rather than the
  implementation usually belongs in `docs/`, with the comment
  reduced to a pointer.
<!-- shared-block-end -->

Report findings as a bullet list. For each finding,
state the file, line, and whether it's blocking (must
fix before push) or advisory (can address later).

### 2b. Test review

| Setting | Value  |
|---------|--------|
| Model   | sonnet |
| Effort  | medium |

**Brief for sub-agent:**

Review the diff (`git diff develop...HEAD`) for test
coverage:

- Does every new public function, endpoint, or SPICE
  packet path have test coverage?
- Do the tests include adversarial cases (malformed
  SPICE messages, oversized lengths, malformed JSON,
  missing fields, expired tokens, wrong tickets)?
- Are there any assertions that test implementation
  details rather than behaviour (fragile tests)?
- Are there any new modules, endpoints, or hypervisor
  backends with zero test coverage that should have at
  least basic tests?
- If the diff touches the tempest plugin or
  `loadtests/`, do the integration tests still assert
  the user-visible behaviour, not just that the call
  didn't error?

Also verify:
- All existing tests still pass (wave 1 already
  confirmed this, so just check the wave 1 result).
- Note whether the tempest plugin in
  `tempest-plugin/kerbside_tempest_plugin/` should be
  re-run end-to-end to verify integration behaviour for
  this diff.

Report findings as a bullet list grouped by file.

### 2c. Documentation review

| Setting | Value  |
|---------|--------|
| Model   | sonnet |
| Effort  | medium |

**Brief for sub-agent:**

Check that documentation matches the current code
state. Read the diff (`git diff develop...HEAD`) and
verify:

<!-- shared-block: readme-discipline v1 -->
README discipline (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/readme-discipline.md`):

- New user-visible features are documented in `docs/` (and
  `ARCHITECTURE.md` / `AGENTS.md` where appropriate), not by
  adding bullets to `README.md`.
- `README.md` is a pitch: what the project is, who it is for,
  minimal installation instructions, a small number of usage
  examples, and curated absolute links into `docs/`. It only
  changes when the pitch, the install story, or the
  documentation links change.
- README growth is itself a finding: if the diff adds README
  content that belongs in `docs/`, flag it as blocking and
  move it.
<!-- shared-block-end -->

<!-- shared-block: llm-doc-discipline v1 -->
AGENTS.md and ARCHITECTURE.md discipline (shared block; do not
edit -- the canonical copy lives in shakenfist/development at
`templates/shared-blocks/llm-doc-discipline.md`):

- `AGENTS.md` is a working guide: the conventions, invariants and
  gotchas an agent cannot infer by reading the code, plus curated
  links into `docs/`. It is loaded into every session, so every
  line costs context on every task.
- `ARCHITECTURE.md` is a map: the component inventory, how data
  moves between components, and why the shape is the way it is.
  A deep dive on one subsystem belongs in `docs/`, where humans
  benefit from it too.
- One canonical home per fact. If `docs/` covers it, link to it
  instead of restating it -- and the same rule applies between
  `AGENTS.md` and `ARCHITECTURE.md`.
- Neither file is a reference manual, a runbook, or a changelog.
  CLI flags, configuration keys, wire protocols, step-by-step
  procedures and plan history go to `docs/`.
- Growth in either file is itself a finding: if the diff adds
  content that belongs in `docs/`, flag it as blocking and move
  it.
<!-- shared-block-end -->

- `ARCHITECTURE.md` reflects any change to the shape of
  the system: new or modified proxy components,
  hypervisor backends, channel types, or the connection
  lifecycle.
- `AGENTS.md` reflects any change to a convention — a
  new invariant or gotcha an agent cannot infer from
  the code. New dependencies and build commands are
  documented in `docs/development.md` instead.
- Protocol documentation in `docs/` is consistent with
  the implementation. In particular: if a packet type,
  capability, or channel was touched, the matching
  page (`docs/channel-protocols.md`,
  `docs/spice-link-protocol.md`,
  `docs/vd-agent-protocol.md`,
  `docs/compression-protocols.md`,
  `docs/usb-redirection.md`, `docs/scancodes.md`) has
  been reviewed.
- Plan files in `docs/plans/` are up to date —
  completed phases are marked complete, deferred items
  are listed.

<!-- shared-block: plan-phase-references v1 -->
Plan phase references (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-phase-references.md`):

- Documentation outside plans directories describes the current
  state of the software, not the history of how it was built. Do
  not write "implemented in phase 5" or "since phase 3 of the
  two-tier CI plan": a reader wants to know whether a feature
  exists, not which phase of which plan delivered it.
- If a documented behaviour is implemented, describe it plainly.
  If it is planned but not yet implemented, link to the master
  plan in `docs/plans/` instead of citing a phase number.
- Reserve the word "phase" for plan documents. A procedural
  document describing a live multi-stage process (a release
  runbook, say) should call its stages "steps" or "stages", so
  that a phase reference in `docs/` is always a plan smell.
- The consistency audit greps `README.md` and `docs/` (excluding
  plans directories) for "phase <number>". Append
  `<!-- audit-ok: phase-reference -->` to a line only when the
  reference is genuinely not about an implementation plan.
<!-- shared-block-end -->
- If the changes affect the hypervisor-facing contract,
  note whether `shakenfist/kerbside-patches` needs a
  matching update.
- If client behaviour changed in a way Ryll cares
  about, note whether `shakenfist/ryll/docs/` needs a
  matching update.

Report findings as a bullet list. "No documentation
gaps found" is a valid answer.

### 2d. Security review

| Setting | Value |
|---------|-------|
| Model   | opus  |
| Effort  | high  |

**Brief for sub-agent:**

Security review of the diff (`git diff develop...HEAD`).
This requires careful judgment — read the actual code,
not just the diff summary.

Kerbside sits between untrusted SPICE clients and
trusted backend hypervisors, holds short-lived tickets,
proxies binary protocol traffic, exposes a REST API, and
maintains an audit log. The following classes matter:

- **Input validation:** Could malformed SPICE messages
  cause unhandled exceptions, unbounded memory
  allocation, or pass-through of attacker-controlled
  lengths to the backend? Look for unchecked
  `struct.unpack` results, unbounded `read()` calls,
  and integer fields used as allocation sizes or
  offsets without bounds checking.
- **Authentication and authorisation:** Are API
  endpoints correctly gated by the documented
  decorator? Are SPICE-level tickets validated against
  the expected source / VM / user? Is there any
  endpoint that should require auth but doesn't?
- **Token / ticket lifecycle:** Are tickets and tokens
  generated with sufficient entropy
  (`secrets`, not `random`)? Are they single-use where
  the design says so? Are they invalidated on session
  end? Are they ever logged?
- **Credential handling:** Are passwords, tickets,
  CA private keys, and connection strings handled
  safely? Are any logged at info / debug level? Are
  they ever returned in API responses?
- **TLS safety:** Is certificate validation correct on
  both client-facing and backend-facing connections?
  Are there paths where TLS could be silently
  downgraded? Is CA bundle handling sound?
- **SQL safety:** Are all queries parameterised through
  SQLAlchemy? Any raw SQL or `.format()`-built queries?
- **SSRF / file access:** Does any new code fetch URLs
  or open file paths derived from user input without
  validation?
- **Audit log integrity:** Are all state-changing
  operations audited? Is the audit event taxonomy
  consistent? Could a caller suppress or forge an
  audit event?
- **Resource exhaustion:** Could a malicious client
  cause unbounded memory growth, file descriptor
  leaks, connection-pool exhaustion, or CPU spin? Is
  there a per-connection or per-token limit?
- **Migrations:** Do alembic revisions destroy data
  that might be needed for rollback? Is the downgrade
  path safe?

Report findings with severity (critical / high /
medium / low / informational). For each finding,
state the file, line, the vulnerability class, and a
recommended fix.

## Management session checklist

After all agents complete, the management session
should:

- [ ] Wave 1 passed (flake8, tests, style grep).
- [ ] Wave 2 findings reviewed.
- [ ] Any blocking findings from 2a/2b/2c have been
      fixed and re-verified.
- [ ] Any security findings from 2d have been
      assessed — critical and high must be fixed before
      push.
- [ ] The commit history is clean (no fixup commits
      that should be squashed, no accidental files,
      no committed `kerbside/_version.py` or other
      build artefacts).
- [ ] The branch is up to date with the target branch
      (rebase if needed).
- [ ] Ready to push.
