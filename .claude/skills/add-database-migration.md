# Add Database Migration

When creating a new Alembic database migration for Kerbside:

1. Create the migration file:
   ```bash
   cd /home/mikal/src/shakenfist/kerbside
   alembic revision -m "description_of_changes"
   ```

2. Edit the generated file in `alembic/versions/` to implement both
   `upgrade()` and `downgrade()` functions.

3. Follow existing migration patterns in `alembic/versions/` for style.

4. Update `kerbside/db.py` with any new models, columns, or queries
   that correspond to the schema change.

5. If the migration adds or modifies tables, update `docs/schema.md`
   and `docs/schema.html` to reflect the new schema.

6. Add or update unit tests in `kerbside/tests/unit/` to cover any
   new database operations.

7. Run `tox -e py3` to verify tests pass with the schema change.
