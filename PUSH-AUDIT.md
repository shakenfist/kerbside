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

**Note:** The `tools/audit/wave1.sh` and
`tools/audit/wave2-mechanical.sh` scripts referenced
below need to be created for this repo. Adapt them from
`shakenfist/ryll/tools/audit/` as a starting point; the
mechanical portions translate well, but the lint /
test commands change from cargo to tox and the
style-grep set changes from Rust-flavoured to
Python-flavoured.

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
  the diff vs `develop`, advisory check for trailing
  whitespace on touched lines, advisory check that
  string literals in changed Python files prefer single
  quotes (per project convention)

Exit codes:

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | all wave 1 checks passed             |
| 1    | flake8 failed                        |
| 2    | py3 test suite failed                |
| 3    | raw `print()` found in non-test code |
| 4    | bare `except:` found                 |

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

- `ARCHITECTURE.md` reflects any new or modified proxy
  components, hypervisor backends, channel types, or
  the connection lifecycle.
- `AGENTS.md` reflects any new dependencies, build
  commands, or conventions.
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
