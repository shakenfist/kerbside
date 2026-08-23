---
name: add-source-type
description: Add a new cloud console source to Kerbside, from the source class through registration, tests and documentation. Use when wiring Kerbside up to a cloud platform it does not discover consoles from yet.
---

# Add New Cloud Source Type

When adding a new cloud source type to Kerbside:

1. Create a new file in `kerbside/sources/` following the pattern of
   existing sources (`shakenfist.py`, `ovirt.py`).

2. Inherit from `BaseSource` in `kerbside/sources/base.py`.

3. Implement the `__call__()` method to yield console entries as dicts
   with keys: `source`, `uuid`, `name`, `hypervisor`, `port`.

4. Implement `close()` for any cleanup (API connections, etc.).

5. Register the new source type in `kerbside/main.py:_parse_sources()`
   by adding an `elif` branch for the new type.

6. Add the new cloud client library to `pyproject.toml` as an optional
   dependency (commented out in main dependencies, listed in test
   dependencies if testable).

7. Add functional tests in `kerbside/tests/functional/` following the
   pattern of `test_openstack.py` or `test_shakenfist.py`.

8. Document the new source type in `docs/console-sources.md`.

9. Update `ARCHITECTURE.md` to include the new source in the Source
   Abstraction table.

10. Run `tox -e py3` and `tox -e flake8` to verify.
