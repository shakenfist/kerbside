# Phase 4: a CI lane for the compose demo

Master plan: [PLAN-demo-install.md](PLAN-demo-install.md)

Planned at medium effort, as the master plan specifies. The
survey moved one thing out of medium territory, though: this
lane would be the **first container build in kerbside CI**, so
the phase leads with a runner probe rather than assuming a
working Docker daemon (finding 5).

## Situation

Phase 3 built `demo/`. Phase 5 will point `docs/installation.md`
at it, which makes it a documented, user-facing path. Nothing
in CI exercises a container build, a compose stack, or
`kerbside db upgrade` on the wheel-install path.

The argument for this phase stopped being hypothetical while
the phase was being planned. Renovate merged #330 on
2026-08-17, bumping `demo/docker-compose.yml` from `mariadb:11`
to `mariadb:12` — a database major version, under the demo,
with nothing to run it. I verified it by hand during the survey
(finding 7) and it is fine, but "a maintainer happened to check"
is exactly the property this phase exists to replace.

## Mission

A CI lane brings up the compose stack against the pull
request's own code and asserts a SPICE session is proxied, so a
change that breaks the documented demo fails visibly.

## Scope

In scope:

- `.github/workflows/demo-compose.yml`, advisory and
  path-filtered.
- `tools/demo/` scripts holding anything longer than a few
  lines, per the operator convention that workflow steps stay
  short.
- A runner probe, `tools/demo/probe-runner.sh`, modelled on
  `tools/direct-qemu/probe-runner.sh`.
- shellcheck enforcement in CI for `tools/` and `demo/`
  (carried over from the phase 3 review).
- Registering the lane in `docs/testing.md` and
  `.claude/CLAUDE.md`.

Out of scope, deliberately:

- **Rewriting `docs/installation.md`.** Phase 5, and it must
  be last.
- **Making the lane a required check.** Decision 1.
- **Testing the PyPI default build.** Decision 4.
- **Fixing the 5900 collision** (finding 10). Recorded, and
  the probe will detect it, but changing the demo's published
  ports is a phase 3 file change with its own documentation
  consequences and does not belong in a CI phase.
- **Publishing a demo image to a registry.** Still a
  release-process question, as phase 3 recorded.

## What the survey found

The draft of this file was written as part of the master plan
commit (`e9d6497`), before phases 1–3 executed, and lightly
touched by the phase 3 review (`bc1fa4a`). It is substantially
stale. The corrections are recorded here and applied at source
in the master plan's Execution table and the `index.md` row as
part of the planning commit, so a later step need not redo it.

**1. Every line citation in the draft is wrong.** Not
approximately — the referenced lines now hold unrelated
content. Corrected:

| Draft said | Actually |
|---|---|
| `docs/testing.md:34` for the `rust.yml` advisory precedent | `docs/testing.md:73` (table row), prose at `:79` |
| `rust.yml:10-22` for the path-filter shape | push filter `rust.yml:12-20`, PR filter `:22-29` |
| `rust.yml:29` for the unsized-`vm`-defaults-to-`xs` note | `rust.yml:36-38`, and it selects `xl`, not the `l` the draft proposes |
| `direct-qemu-functional.yml:33-36` for concurrency | `:30-32` |
| `direct-qemu-functional.yml:96-99` for the `no_proxy` squid note | `:88-92` |

The `rust.yml` filter list also grew two entries in #314
(`tools/stamp-dev-proxy-version.sh`,
`tools/verify-wheel-stamping.sh`), which is why the range
moved.

**2. The ryll feature-flag claim is backwards, and copying the
named file would produce the opposite of what the draft
intends.** The draft says to follow
`direct-qemu-functional.yml`'s ryll build "**without**
`--features digest-decode`, which the oVirt lane's equivalent
step also omits". In fact `direct-qemu-functional.yml:143`
*includes* `--features digest-decode`; the lane that omits it
is the oVirt one at `functional-tests.yml:629`. For a lane
asserting connection rather than pixels,
`functional-tests.yml:629` is the line to copy.

**3. The proxy-wheel build is one step, and not the one
described.** The draft says to "copy the four steps verbatim
from `direct-qemu-functional.yml`'s wheel build (apt
prerequisites, `dtolnay/rust-toolchain@stable`, a
maturin+ziglang venv, `tools/build-proxy-wheel.sh` with
`WHEEL_OUT`)". Reality at
`direct-qemu-functional.yml:157-161`: a single step that makes
a maturin + **setuptools_scm** venv — no ziglang, which is for
cross-compilation and is not needed for a native build — and
calls `tools/direct-qemu/install-proxy-wheel.sh --venv`, which
sets `WHEEL_OUT` itself at `install-proxy-wheel.sh:53`. The
four-step shape the draft describes is `release.yml`'s.

**4. The lane probably does not need to build the Rust proxy
at all, which removes the most expensive thing in the draft.**
The draft's justification for building it: "the
`KERBSIDE_PROXY_PIN` in `pyproject.toml` is deliberately absent
from the committed tree, so a `KERBSIDE_SOURCE=/src` build has
no proxy to install from PyPI." That was true when written and
#314 changed it. `pyproject.toml:34` now carries a
dev-inclusive **floor**, `kerbside-proxy>=0.4.0.dev0`, and the
`.dev0` suffix is what makes pre-releases eligible for that
requirement. Verified rather than reasoned about:

```
$ pip install --dry-run --report - .      # from a clean checkout
kerbside-proxy 0.5.1.dev1
```

That is a dev wheel published from develop by
`dev-proxy-wheel.yml`, and resolving it is precisely what phase
2 of `PLAN-proxy-dev-releases` set out to achieve for
downstream git installs. So a `/src` build pairs a checkout
daemon with a develop-tracking binary on its own, with no cargo
in the lane. See decision 3 for the residual case.

**5. No kerbside workflow uses Docker. At all.** `grep -rn
'docker\|podman\|buildkit' .github/workflows/` returns nothing.
This lane would be the repository's first container build, and
three things the draft silently assumes are unverified on the
private-CI runners:

- a usable Docker daemon and permission to reach it;
- Docker Engine 23.0+, which `demo/Dockerfile` requires by
  name for `RUN --mount=type=bind` under the built-in
  BuildKit frontend;
- egress from *inside* a build container to pypi.org. The
  runners sit behind a squid
  (`direct-qemu-functional.yml:88-92`) and
  `functional-tests.yml:106` points pip at a devpi mirror
  (`http://192.168.1.15:3141/root/pypi/+simple/`). A
  `docker build` inherits neither the runner's proxy
  environment nor its `PIP_INDEX_URL`.

This is the single most likely reason a first attempt at the
lane fails, and it is cheap to find out first. Hence step 4a.

**6. The shellcheck-in-CI gap is real and unchanged.** `grep
-rn pre-commit .github/workflows tox.ini` finds only two hits,
both comments in `pr-address-comments.yml` (lines 16 and 154)
explaining why pre-commit is skipped there. `tox.ini` has
`flake8`, `py3`, `cover`, `genprotos` and `bindep`, and no
shellcheck environment. So the demo's four shell scripts are
checked only where a developer installed the hooks. The phase 3
review's carry-over stands.

**7. Renovate is already changing the demo untested, and the
current develop had never been run.** #330 (`433bc88`,
2026-08-17) bumped the demo database from `mariadb:11` to
`mariadb:12`. Phase 3's end-to-end verification was on
`mariadb:11`. Verified during this survey against
`mariadb:12.3.2`: `docker compose up -d --wait` reaches all
three services healthy, all 9 migrations apply, the proxy
starts, and `kerbside demo token` mints. No action needed — but
this is the phase's own justification, arriving unprompted.

**8. The `.vv` really does carry a live credential.** The
draft's artifact-redaction requirement is well founded:
`kerbside/api.py:374` puts `password=%(token)s` in
`VIRTVIEWER_TEMPLATE`.

**9. A `/src` build needs full git history, so the lane needs
`fetch-depth: 0`.** `demo/Dockerfile` records that
setuptools_scm's git file finder is the only thing installing
`kerbside/sources/` and `kerbside/migrations/`, and
`install-proxy-wheel.sh`'s header notes a shallow clone cannot
count commits since the last `v*` tag. `actions/checkout`
defaults to depth 1. The precedent is already in the tree:
`direct-qemu-functional.yml:100` and
`sf-e2e-functional.yml:113` both set `fetch-depth: 0`.

**10. The demo's fixed port 5900 collides with any host
running a VNC server.** Hit twice on the development host
during this survey; the bind fails with `failed to bind host
port 127.0.0.1:5900/tcp: address already in use` from the
Docker daemon, which does not name what holds it. A CI runner
is a plausible place for the same collision. Out of scope to
fix (see Scope), but the probe should detect it and say so.

**11. A gotcha for anyone writing a compose override in this
phase.** `docker compose` merges list-valued keys such as
`ports` by *appending*, so an override file that lists fewer
ports does not reduce them — the original bindings are still
attempted. Replacing the list needs the `!override` tag
(Compose 2.24+; this host runs v5.4.0). Learned the hard way
while working around finding 10.

Nothing else in the draft's reasoning failed. The tier
decision, the artifact redaction, the negative-case assertions
and the "do not test the PyPI path" argument all survive
scrutiny and are carried forward.

## Decisions

**1. Advisory, path-filtered — not a required check.** Carried
forward from the draft, and confirmed: `docs/testing.md:73`
establishes the precedent with `rust.yml`, and the five
required checks are gate jobs whose names are bound to the
develop ruleset that `tools/check-required-checks.sh` validates
against. Renaming or adding one blocks every merge in the
repository. Not worth it for a demo path.

Path filter:

```
paths:
  - 'demo/**'
  - 'kerbside/migrations/**'
  - 'pyproject.toml'
  - 'docs/installation.md'
  - 'tools/demo/**'
  - '.github/workflows/demo-compose.yml'
```

`docs/installation.md` is deliberately included: the document
and the thing it documents should not be able to drift without
the lane running. `kerbside/migrations/**` and `pyproject.toml`
are there because phase 1's packaging is the part most likely
to break silently — and finding 4 adds a second reason, since
`pyproject.toml` is where the proxy floor lives.

**2. Probe the runner before writing the lane.** Step 4a is a
throwaway workflow that answers finding 5's three questions and
nothing else. It is the cheapest possible way to learn whether
this phase's shape is even viable, and the alternative is
discovering it from a red lane whose failure could be any of a
dozen things. If the probe says the runners cannot build
containers or cannot reach an index from inside a build, **stop
and re-plan** — do not work around it in the lane.

**3. Do not build the Rust proxy in the lane.** Per finding 4,
`pip` resolves a develop-tracking dev wheel on its own. This
drops a cold `cargo build --release` from every run.

The residual case is a pull request that changes
`kerbside/rpc/kerbside.proto` *and* one of this lane's filtered
paths, before `dev-proxy-wheel.yml` has published a wheel for
the new proto. Then the checkout daemon and the PyPI dev wheel
disagree, and `proxy_supervisor.check_contract()` refuses to
launch — `get_binary_contract_hash()` treats a mismatch and an
unanswerable `--contract-hash` alike, so this fails at startup
rather than subtly. The lane will go red for a reason that is
not the demo's fault.

That is an acceptable trade and should be *documented in the
workflow comment* rather than engineered around: the failure is
loud, correctly diagnosed by the daemon's own error, and the
fix is to let the dev wheel publish. Building the proxy in the
lane to avoid it would cost several minutes on every unrelated
run. If it turns out to bite in practice, the fallback is
already written and tested — one step calling
`tools/direct-qemu/install-proxy-wheel.sh --venv`, exactly as
`direct-qemu-functional.yml:157-161` does.

**4. Test `KERBSIDE_SOURCE=/src`, not the PyPI default.**
Carried forward. A lane exercising the default would test the
last release rather than the pull request. Worth restating that
the default genuinely is PyPI again as of `72c5aca` — phase 3
had temporarily reversed it — so this is now a real divergence
between what the lane builds and what a user builds, and the
workflow comment should say so and say why.

**5. shellcheck goes in `tox -e shellcheck`, called from
`sanity_checks` — not in this lane.** This reverses the
draft's stated preference, and it is the decision most likely
to be argued with.

The draft preferred adding a shellcheck step to the new lane on
the grounds that `sanity_checks` is a gate job feeding a
required check. But this lane is path-filtered to `demo/**` and
friends, so a change to `tools/` — 40-odd scripts, the majority
of the shell in the repository — would not trigger it. That
gives the *appearance* of CI shellcheck coverage while leaving
most of the actual shell unchecked, which is worse than the
status quo because it is misleading.

`sanity_checks` is the right home, and the caution about it
does not apply: `.claude/CLAUDE.md` warns against **renaming**
gate jobs, because the ruleset binds their display names.
Adding a step inside `sanity_checks` renames nothing. And the
path filter reaches: `check_paths`' `code` filter
(`functional-tests.yml:81-88`) is `'**'` minus review marks and
`docs/**`, so `demo/**` and `tools/**` both count as code and
`sanity_checks` runs for them.

Match the pre-commit hook's scope exactly (`^(tools|demo)/`,
`-x`, `types_or: [sh, bash, shell]`) so the two cannot disagree
about what passes.

**6. Copy `functional-tests.yml:629` for ryll, not
`direct-qemu-functional.yml:143`.** Per finding 2. This lane
asserts that a SPICE session is established, not what it
renders, so `--no-default-features -p ryll` without
`digest-decode` is correct and cheaper.

**7. Runner size `l`, and never an unsized `vm` label.** A qemu
TCG guest, a MariaDB, a container build and a ryll build on one
runner. `rust.yml:36-38` records that an unsized `vm` label
defaults to `xs` (1 core / 2 GB) in private-ci, which will not
do. `l` rather than `rust.yml`'s `xl` because decision 3
removes the cargo release build that justifies `xl`; the probe
in step 4a should report timings so 4b can revisit this with
evidence rather than guesswork.

**8. `no_proxy: 127.0.0.1,localhost` at job level, and a
concurrency group.** Per `direct-qemu-functional.yml:88-92`
and `:30-32`. Loopback traffic to the published demo ports must
bypass the squid or it returns 503 `ERR_CONNECT_FAIL`. This has
bitten two lanes already; assume it bites here.

## Execution

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | medium | sonnet | none | **Probe first; this step decides whether the rest of the phase is viable.** Write `tools/demo/probe-runner.sh`, modelled closely on `tools/direct-qemu/probe-runner.sh` (read it — same output style, same "print diagnostics, exit non-zero only on a hard blocker" contract). It must report: `docker version` client and server, whether the daemon is reachable as the runner user, whether the server is 23.0+ (`demo/Dockerfile` requires it by name for `RUN --mount=type=bind`), `docker compose version`, whether TCP 5900/5901/13002 are already bound on 127.0.0.1 (finding 10 — the Docker daemon's own bind error does not name the holder, so this must), and whether a throwaway `docker build` that runs `pip download --no-deps kerbside-proxy` can reach an index from *inside* the build (finding 5 — the build inherits neither the runner's `http_proxy` nor `PIP_INDEX_URL`). Exit non-zero for a missing or too-old daemon, or no index reachability; print-and-continue for a bound port. Then add a temporary `.github/workflows/demo-probe.yml`, `workflow_dispatch` only, `runs-on: [self-hosted, vm, debian-12, l]`, that checks out and runs it. Run it, report the output verbatim, and **stop for review before step 4b** — the back brief gates here. Delete the temporary workflow in 4b, keeping the script. |
| 4b | high | sonnet | none | Write `.github/workflows/demo-compose.yml` per the Decisions above. High effort rather than medium because the runner facts from 4a have to be read and applied rather than followed from a recipe. Advisory, path-filtered per decision 1; `fetch-depth: 0` (finding 9); `no_proxy` and concurrency per decision 8; `runs-on` per decision 7. **No cargo step** (decision 3) — and put decision 3's residual-case reasoning in a comment, so the next person to see a contract-hash failure knows it is expected and why. Steps: probe, then `docker compose config` and `docker compose build` as a fast schema and Dockerfile check ahead of anything slow, then `tools/demo/lane-up.sh`, then `tools/demo/lane-assert.sh`. Finish with an `if: always()` artifact upload of `docker compose logs` for all three services, the ryll output, and the `.vv` **with the `password=` line redacted** (finding 8: `kerbside/api.py:374` puts a live console token there, and CI artifacts are downloadable). Delete `.github/workflows/demo-probe.yml`. Keep workflow steps short — anything beyond a few lines belongs in `tools/demo/`. |
| 4c | high | sonnet | none | Write `tools/demo/lane-up.sh` and `tools/demo/lane-assert.sh`, modelled on `tools/direct-qemu/lane-up.sh` in structure and comment style. `lane-up.sh`: build with `KERBSIDE_SOURCE=/src`, `docker compose up -d --wait`, and on failure print `docker compose logs` for the service that is not healthy rather than a bare timeout. `lane-assert.sh`: run `demo/get-console.sh`; assert the `.vv` carries `tls-port=`, `host-subject=` and a `ca=` field holding an escaped PEM; drive ryll headless against the TLS port and assert the link handshake completes and the main channel opens (read `tools/direct-qemu/smoke-client.py` and reuse its assertion approach — do not write a new SPICE client driver); then both negative cases — `docker compose stop spice-target` must make a fresh console request fail in bounded time rather than hang, and appending a dummy `type: ovirt` entry to `demo/sources.yaml` must make `kerbside demo token` refuse and name the offending source. Restore `demo/sources.yaml` from an EXIT trap so a mid-assertion failure does not leave the tree dirty. Note that `demo/get-console.sh` already proves the TLS leg internally — it verifies the presented certificate against the CA embedded in the `.vv` — so do not reimplement that; assert the fields and let ryll cover the SPICE handshake. |
| 4d | medium | sonnet | none | Add shellcheck to CI per decision 5. New `[testenv:shellcheck]` in `tox.ini` mirroring the pre-commit hook's scope exactly — `^(tools|demo)/`, `-x`, shell files only — so the two cannot disagree; read `.pre-commit-config.yaml:21-27` for the authoritative settings. Call it from `sanity_checks` in `functional-tests.yml` (the job starts at line 94) as a step alongside the existing flake8 invocation. Do not rename any job. Demonstrate it fails: introduce a deliberate shellcheck violation in a `demo/` script, show the failure, revert it. |
| 4e | low | haiku | none | Register the lane. One row in `docs/testing.md`'s workflow table (model it on the `rust.yml` advisory row at line 73) and one bullet in the "Neither tier" list in `.claude/CLAUDE.md`'s CI Workflows section. Do not restructure either document. |
| 4f | high | sonnet | worktree | Prove the lane fails when it should — the only evidence that matters for a new lane. On a scratch branch, break the demo four ways in sequence and confirm the lane goes red each time *for the right reason*, capturing the message: (i) point `demo/sources.yaml` at a wrong `insecure_port`; (ii) set `KERBSIDE_PROXY_HOST_SUBJECT` to a mismatched string, which must fail the TLS assertion rather than silently falling back to plaintext; (iii) revert phase 1's packaging so `kerbside db upgrade` cannot find its migrations; (iv) break the compose schema, which must fail at `docker compose config` in seconds rather than after a full image build. Worktree isolation because this step deliberately breaks the tree. Report the four messages. Do not merge the scratch branch. |

## Risks and mitigations

**The runners cannot build containers, or a build cannot reach
a package index.** The likeliest failure, and the whole reason
for step 4a. Mitigation: the probe answers it before any lane
is written, and decision 2 says to stop and re-plan rather than
work around it. Checked by the management session reading 4a's
verbatim output, not a summary of it.

**The lane goes red for a proto/dev-wheel skew rather than a
demo fault.** Accepted per decision 3. Mitigation: the workflow
comment must explain the failure mode, and the daemon's own
refusal message already names the cause. If it recurs, the
fallback step is specified in decision 3 and needs no new
design.

**Something on a runner holds 5900.** Finding 10. Mitigation:
the probe reports bound ports by name so the diagnosis is not
the Docker daemon's uninformative bind error. Fixing the port
choice is explicitly out of scope; if the probe shows a
collision, that becomes a phase 3 follow-up with its own
documentation consequences.

**The lane is slow enough that people stop reading it.** A
container build plus a stack start plus ryll. Mitigation:
decision 3 removes the cargo build; 4b puts `docker compose
config` first so schema errors fail in seconds; the path filter
keeps it off unrelated pull requests. 4a reports timings so
decision 7's runner size can be revisited with evidence.

**shellcheck in `sanity_checks` slows a gate job.** It is a
lint pass over some fifty small files; seconds. Mitigation: if
4d finds otherwise, move it to its own job rather than
weakening the scope, and say so.

## Definition of done

Falsifiable, each checkable by running something:

- [ ] `tools/demo/probe-runner.sh` runs on a private-CI runner
      and its output is recorded in this file, including the
      Docker server version and whether a build reached an
      index.
- [ ] `.github/workflows/demo-probe.yml` does not exist at the
      end of the phase (`test ! -e`).
- [ ] The lane is green on a pull request touching `demo/`.
- [ ] The lane is red, with a message naming the actual cause,
      for each of 4f's four deliberate breakages. The four
      messages are quoted in this file.
- [ ] The lane does not run on a pull request that touches
      only `docs/` outside `installation.md` — demonstrated,
      not assumed.
- [ ] `git diff` shows no change to the develop ruleset and no
      new required check, and
      `tools/check-required-checks.sh` still passes.
- [ ] `tox -e shellcheck` passes on a clean tree, and was
      demonstrated to fail on a deliberate violation in
      `demo/`.
- [ ] `tox -e shellcheck`'s file scope and the
      `.pre-commit-config.yaml` shellcheck hook's scope are
      the same string.
- [ ] `docs/testing.md` and `.claude/CLAUDE.md` both list the
      lane.
- [ ] A failure artifact from a real red run has been
      downloaded and inspected: it contains the three
      services' logs and **no live console token**
      (`grep -c '^password='` on the uploaded `.vv` is 0).
- [ ] No cargo or Rust step in the workflow, and the residual
      contract-skew case is explained in a comment.

## Registration

Recorded in the master plan's Execution table and in
`docs/plans/index.md`. `docs/plans/order.yml` is for master
plans only and is not touched — and this repository has no
`order.yml` at all, which the phase 3 plan also recorded.

## Future work

- **A periodic check of the PyPI default build.** Decision 4
  keeps it out of the per-PR lane. A nightly is the natural
  home, and it would have caught nothing so far, but it is the
  only thing that would notice the released package breaking
  the demo.
- **Move the demo off port 5900** (finding 10), or make the
  ports configurable. Needs a phase 3 file change and a
  documentation pass.
- **Publish a demo image**, so `compose up` does not build.
  Carried over from phase 3; still a release-process and
  image-signing question.

## Back brief

**Gate at the end of step 4a.** The probe output decides
whether this phase's shape survives. Do not start 4b until the
management session has read 4a's verbatim output and confirmed
the runners can build containers and reach a package index from
inside a build. This is cheap to check and expensive to
discover later.

Before implementation begins, the implementing session should
be able to state:

1. Why there is no cargo step, and what happens if a pull
   request changes the proto and `demo/` together.
2. Why shellcheck goes in `sanity_checks` rather than in this
   lane, and why that does not touch a gate job's name.
3. Which file to copy the ryll build from, and why it is not
   the direct-qemu lane.
4. Why the lane needs `fetch-depth: 0`.
