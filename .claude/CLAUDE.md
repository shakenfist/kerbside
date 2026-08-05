# Kerbside Project Instructions

## Overview

Kerbside is a SPICE VDI protocol proxy that provides remote console access
to VMs across Shaken Fist, OpenStack, and oVirt clouds. It handles SPICE
protocol negotiation, authentication, and bidirectional traffic relay.
The data plane is a Rust binary (`rust/kerbside-proxy/`); the Python
package provides the REST API, database, console-source discovery, and
the daemon that supervises the Rust proxy.

## Build and Test

```bash
# Unit tests
tox -e py3

# Style checks
tox -e flake8

# Coverage report
tox -e cover

# Check OS dependencies
tox -e bindep
```

## Architecture Quick Reference

- **Split data/control plane**: the Python daemon launches and supervises
  the Rust `kerbside-proxy` binary, which terminates TLS, drives the SPICE
  handshake, and relays traffic through an inspection-first SPICE firewall
- **Daemon-to-proxy contract**: gRPC over a Unix socket
  (`kerbside/rpc/kerbside.proto`); cross-node coordination is via the
  shared database, never direct RPC
- **Database**: MySQL/MariaDB via SQLAlchemy + Alembic migrations
- **API**: Flask REST with JWT auth and Prometheus metrics
- **Sources**: pluggable console discovery (Shaken Fist, oVirt, OpenStack)

## Key Files

| File | Purpose |
|------|---------|
| `rust/kerbside-proxy/` | The SPICE proxy, start here for connection handling; builds in Docker via its Makefile |
| `kerbside/proxy_supervisor.py` | Finds, launches, and supervises the Rust proxy binary |
| `kerbside/api.py` | REST API endpoints and web UI |
| `kerbside/db.py` | Database models and queries |
| `kerbside/main.py` | Daemon entry point and maintenance loop |
| `kerbside/config.py` | Pydantic-based configuration |
| `kerbside/rpc/kerbside.proto` | gRPC contract between the daemon and the Rust proxy |
| `kerbside/sources/` | Cloud source implementations |
| `tools/pin-indirect-dependencies.sh` | Regenerates the pinned indirect dependency block in `pyproject.toml`; never hand-edit between its markers |

## Code Style

- Follow PEP 8
- Single quotes for strings, double quotes for docstrings
- Wrap lines at 80 characters
- Use `LOG.with_fields({...}).info()` for structured logging
- Add audit events for security-sensitive operations
- Use mypy type hints

## Database Migrations

```bash
alembic revision -m "description_of_changes"
# Edit alembic/versions/<new_file>.py
alembic upgrade head
```

## Review Tracking

Review marks (`REVIEWS.md`, `.vscode/*.weaudit*`) are maintained with
`tools/review-tracking.sh` (`stamp`, `prune`, `regen`, `next`, `status`).
The commit that adds a mark must be signed -- the signature is the
attestation. Signing is per-clone config, so a fresh clone needs:

```bash
git config gpg.format x509
git config gpg.x509.program gitsign
git config commit.gpgsign true
git config tag.gpgsign true
```

Check with `git log --format='%h %G? %s'` before pushing review marks;
`N` means unsigned. Never edit `REVIEWS.md` by hand. See
`docs/development.md` for details.

## Documentation

Protocol documentation lives in `docs/`. When making user-visible changes,
check whether `docs/` needs updating. See `docs/index.md` for the full
documentation index.

## CI Workflows

- `functional-tests.yml` - Lint, unit tests, oVirt/OpenStack integration
- `rust.yml` - Rust proxy lint, tests, and wheel build
- `direct-qemu-functional.yml` - End-to-end proxy checks against a local qemu
- `pr-address-comments.yml` - Bot-triggered comment addressing
- `pr-re-review.yml` - Bot-triggered re-review
- `pr-retest.yml` - Bot-triggered functional test re-run
- `release.yml` - PyPI release via signed tags
- `renovate.yml` - Dependency updates
- `codeql-analysis.yml` - Security scanning
- `export-repo-config.yml` - Repo config archival

## Skills

Claude skills are available in `.claude/skills/` for common tasks:
- `add-database-migration.md` - Creating Alembic database migrations
- `add-source-type.md` - Adding new cloud source implementations
