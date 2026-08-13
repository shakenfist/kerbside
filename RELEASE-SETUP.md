# Release Infrastructure Setup

This document describes how to configure PyPI and GitHub to enable automated
releases using GitHub Actions with Sigstore signing.

## Overview

The release process uses:

- **PyPI Trusted Publishers (OIDC)**: No API tokens needed; PyPI trusts the
  GitHub Actions workflow directly
- **Sigstore/gitsign**: Keyless signing for git tags (no GPG private key
  management)
- **GitHub Environments**: Required reviewer approval before releases proceed
- **Protected Tags**: Restrict who can create release tags

## One-Time Setup Steps

### 1. Configure PyPI Trusted Publisher

This allows the GitHub Actions workflow to publish to PyPI without storing any
API tokens.

1. Log in to [pypi.org](https://pypi.org) with your account
2. Navigate to your project: `kerbside` (or create it if it doesn't exist)
3. Go to **Settings** (or **Your projects** > **Manage**)
4. Click **Publishing** in the left sidebar
5. Under **Trusted Publishers**, click **Add a new publisher**
6. Fill in the form:
   - **Owner**: `shakenfist`
   - **Repository name**: `kerbside`
   - **Workflow name**: `release.yml`
   - **Environment name**: `release` (must match the workflow)
7. Click **Add**

The workflow will now be able to publish without any stored credentials.

**Note**: If the `kerbside` package doesn't exist on PyPI yet, you can add a
"pending" trusted publisher before the first release. Go to your PyPI account
settings and look for "Add a new pending publisher".

#### 1a. Second trusted publisher for `kerbside-proxy`

Kerbside ships two PyPI packages, released in lockstep from the same `v*`
tag by the same `release.yml` workflow (see "Two-package lockstep release"
below):

- **`kerbside`** — the pure-Python daemon/API/CLI (setuptools + setuptools_scm).
- **`kerbside-proxy`** — the Rust SPICE proxy, a maturin `bindings = "bin"`
  binary wheel (manylinux x86_64 and aarch64).

Repeat the trusted-publisher setup above for a **second** PyPI project named
`kerbside-proxy`, with the identical configuration (Owner `shakenfist`,
Repository `kerbside`, Workflow `release.yml`, Environment `release`). Because
it is the same workflow and environment, no new secrets are involved. Add it
as a **pending** publisher before the first release if the project does not
exist on PyPI yet.

#### Two-package lockstep release

Both packages are built and published from one `v*` tag:

- `setuptools_scm` derives the `kerbside` version from the tag.
- `tools/stamp-proxy-version.sh` stamps that same version into the crate's
  `Cargo.toml` (which maturin reads for the wheel) and inserts an exact
  `kerbside-proxy==<version>` pin into `kerbside`'s dependency list, so
  `pip install kerbside==X.Y.Z` transitively installs
  `kerbside-proxy==X.Y.Z`.
- `kerbside-proxy` is published **before** `kerbside` (the `publish-pypi`
  job depends on `publish-proxy-pypi`), so `kerbside` is never published
  referencing a proxy version that failed to publish.
- No sdist is published for `kerbside-proxy` (wheels only); an unsupported
  platform gets a clean "no matching distribution" from pip.

### 2. Create GitHub Environment with Required Reviewers

This ensures releases only happen after explicit approval.

1. Go to the repository on GitHub: `shakenfist/kerbside`
2. Click **Settings** > **Environments**
3. Click **New environment**
4. Name it: `release`
5. Click **Configure environment**
6. Under **Environment protection rules**:
   - Check **Required reviewers**
   - Add yourself (and any other trusted maintainers)
   - Optionally add a **Wait timer** (e.g., 5 minutes) for additional safety
7. Under **Deployment branches and tags**:
   - Select **Selected branches and tags**
   - Add a rule: `v*` (to only allow release tags)
8. Click **Save protection rules**

### 3. Configure Protected Tags (Recommended)

This prevents unauthorized users from creating release tags.

1. Go to **Settings** > **Rules** > **Rulesets**
2. Click **New ruleset** > **New tag ruleset**
3. Configure:
   - **Ruleset name**: `Release tags`
   - **Enforcement status**: `Active`
   - **Target tags**: Add pattern `v*`
   - **Rules**: Check **Restrict creations** and **Restrict deletions**
   - **Bypass list**: Add repository admins or specific maintainers
4. Click **Create**

### 4. Verify Sigstore/Rekor Access

No configuration needed. Sigstore is a public service that:

- Signs artifacts using OIDC identity (the GitHub Actions workflow identity)
- Records signatures in a public transparency log (Rekor)
- Requires no key management

Verification can be done by anyone using `cosign` or `gitsign verify`.

### 5. Configure Dev Release Publishing

Dev releases publish unattended on qualifying pushes to `develop` (see
"Dev releases" below), so they need their own GitHub environment and their
own PyPI trusted publisher, separate from the approval-gated `release`
environment used for tagged releases.

#### 5a. Create the `dev-release` GitHub Environment

1. Go to the repository on GitHub: `shakenfist/kerbside`
2. Click **Settings** > **Environments**
3. Click **New environment**
4. Name it: `dev-release`
5. Click **Configure environment**
6. Under **Environment protection rules**:
   - Leave **Required reviewers** unchecked. This is deliberate: the whole
     point of a dev release is that consumers installing unreleased
     kerbside from git (notably upstream Kolla image builds) resolve a
     working proxy wheel from PyPI without anyone in the loop. Gating it
     on approval would just recreate the tagged-release workflow under a
     different name.
7. Under **Deployment branches and tags**:
   - Select **Selected branches and tags**
   - Add a rule: `develop`. This is the only thing stopping a feature
     branch (or a `workflow_dispatch` run against one) from publishing a
     dev wheel through this environment.
8. Click **Save protection rules**

#### 5b. Register the Second Trusted Publisher for Dev Releases

`kerbside-proxy` already has a PyPI project from step 1a; add a **second**
trusted publisher to it (a PyPI project can have multiple trusted
publishers, one per workflow/environment pair):

1. Log in to [pypi.org](https://pypi.org), navigate to the
   `kerbside-proxy` project, **Publishing**, **Add a new publisher**
2. Fill in the form:
   - **Owner**: `shakenfist`
   - **Repository name**: `kerbside`
   - **Workflow name**: `dev-proxy-wheel.yml`
   - **Environment name**: `dev-release` (must match the workflow)
3. Click **Add**

This is deliberately a separate publisher entry from the `release.yml` /
`release` one added in step 1a — the two workflows publish through
different environments with different trust postures (see "Dev releases"
below), and PyPI trusted publishers are scoped per workflow+environment,
not per project.

## How Releases Work

1. A maintainer pushes a tag matching `v*` (e.g., `v0.1.0`)
2. The `release.yml` workflow triggers
3. The workflow builds the package and waits for environment approval
4. A required reviewer approves the release in GitHub's UI
5. The workflow:
   - Creates a signed git tag using gitsign (Sigstore)
   - Generates Sigstore attestations for the built artifacts
   - Publishes to PyPI using OIDC (no tokens)
   - Creates a GitHub Release with the artifacts

### Dev releases

In addition to tagged releases, `.github/workflows/dev-proxy-wheel.yml`
publishes unreleased `kerbside-proxy` dev wheels to PyPI:

- **Trigger**: pushes to `develop` that change the proxy binary's inputs
  (path-filtered on `rust/**`, `kerbside/rpc/kerbside.proto`,
  `tools/build-proxy-wheel.sh`, `tools/stamp-dev-proxy-version.sh`, and the
  workflow file itself) — an unrelated change on `develop` does not trigger
  a new dev release.
- **Versioning**: the version comes from `setuptools_scm`
  (`MAJOR.MINOR.PATCH.devN`, e.g. `0.4.1.dev159`, monotonically increasing
  with commits since the last tag) and is stamped as a static
  `[project] version` into `rust/kerbside-proxy/pyproject.toml` by
  `tools/stamp-dev-proxy-version.sh`. `Cargo.toml` is left untouched — dev
  versions are not valid Cargo semver.
- **Manual dispatch**: the workflow also accepts `workflow_dispatch`, with
  a `dry_run` input that defaults to `true`. `dry_run: true` builds the
  wheel without publishing; `dry_run: false` publishes unconditionally,
  which is how the PyPI project gets bootstrapped (or a dev release
  force-published outside the normal path-filtered trigger).
- **Trust posture**: dev wheels get build provenance attestations, the
  same as tagged releases, but they are **not** covered by the Sigstore
  tag-signing tagged releases get — there is no `v*` tag for a dev build to
  sign. Publishing runs through the `dev-release` environment, which has
  no required reviewers (see "Configure Dev Release Publishing" above), so
  consumers of dev wheels are trusting CI provenance, not a human-approved,
  tag-signed release.
- The approval-gated `release` environment and the exact lockstep version
  pins it produces (see "Two-package lockstep release" above) are
  unaffected — dev releases only ever publish `kerbside-proxy`, never
  `kerbside` itself, so there is no cross-pinning to worry about.

## Verifying Releases

### Verify Git Tag Signature

```bash
# Install gitsign
go install github.com/sigstore/gitsign@latest

# Verify a tag
gitsign verify --certificate-identity-regexp='.*' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    v0.1.0
```

### Verify PyPI Package Attestation

```bash
# Install pip-audit or use the PyPI web interface
pip install pip-audit

# PyPI shows attestation status on the package page
# Look for the "Provenance" section
```

### Verify with Cosign

```bash
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Verify artifact attestation
cosign verify-attestation \
    --certificate-identity-regexp='.*' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    kerbside-0.1.0.tar.gz
```

## Troubleshooting

### "Environment not found" Error

Ensure the environment name in the workflow (`release`) exactly matches the
environment created in GitHub Settings.

### "Publisher not found" Error on PyPI

- Verify the workflow filename matches exactly (case-sensitive)
- Verify the environment name matches exactly
- Ensure you're using the correct PyPI account (not TestPyPI)

### Tag Signature Verification Fails

- Ensure you're checking against the correct OIDC issuer
- The certificate identity will be the workflow's identity, not a personal
  email

### Approval Not Requested

- Ensure the tag matches the deployment branch/tag rules (e.g., `v*`)
- Check that required reviewers are configured on the environment

## Security Considerations

- **No long-lived secrets**: Neither GPG keys nor PyPI tokens are stored
- **Audit trail**: All releases are logged in GitHub Actions and Sigstore's
  Rekor transparency log
- **Multi-party approval**: Required reviewers prevent unilateral releases
- **Immutable provenance**: Sigstore attestations cryptographically link
  artifacts to the exact source commit
