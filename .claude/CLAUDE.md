# Kerbside Project Instructions

## Overview

Kerbside is a SPICE VDI protocol proxy that provides remote console access
to VMs across Shaken Fist, OpenStack, and oVirt clouds. It handles SPICE
protocol negotiation, authentication, and bidirectional traffic relay.

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

- **Multiprocess model**: main process spawns proxy workers per connection
- **State machine**: SpiceTLSSession progresses through handshake, auth, relay
- **Database**: MySQL/MariaDB via SQLAlchemy + Alembic migrations
- **API**: Flask REST with JWT auth and Prometheus metrics
- **Sources**: pluggable console discovery (Shaken Fist, oVirt, OpenStack)

## Key Files

| File | Purpose |
|------|---------|
| `kerbside/proxy.py` | Core proxy, start here for connection handling |
| `kerbside/api.py` | REST API endpoints and web UI |
| `kerbside/db.py` | Database models and queries |
| `kerbside/main.py` | Daemon entry point and maintenance loop |
| `kerbside/config.py` | Pydantic-based configuration |
| `kerbside/spiceprotocol/` | SPICE protocol packet handling |
| `kerbside/sources/` | Cloud source implementations |

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

## Documentation

Protocol documentation lives in `docs/`. When making user-visible changes,
check whether `docs/` needs updating. See `docs/index.md` for the full
documentation index.

## CI Workflows

- `functional-tests.yml` - Lint, unit tests, oVirt/OpenStack integration
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
