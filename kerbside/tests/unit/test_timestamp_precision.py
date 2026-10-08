import io
from unittest import mock

from alembic import command as alembic_command
from sqlalchemy import Float
from sqlalchemy.dialects import mysql
import testtools

from kerbside import db
from kerbside import main
from kerbside.config import config


# Every column that holds a time.time() float, as (table, column).
_TIME_COLUMNS = [
    ('sf_token_jtis', 'expiry'),
    ('sf_token_keys', 'fetched_at'),
    ('session_terminations', 'requested_at'),
]


def _offline_sql(direction, revisions):
    """Render a migration range as MySQL, with no database needed."""
    cfg = main._alembic_config()
    buffer = io.StringIO()
    cfg.output_buffer = buffer
    with mock.patch.object(
            config, 'SQL_URL', 'mysql://kerbside:pw@db/kerbside'):
        getattr(alembic_command, direction)(cfg, revisions, sql=True)
    return buffer.getvalue()


class ModelPrecisionTestCase(testtools.TestCase):
    """No model column may be single precision on MySQL or MariaDB.

    sa.Float compiles to FLOAT there, a 24-bit mantissa that holds an epoch
    time only to the nearest 128 seconds. Unit tests run against sqlite,
    which stores every float as eight bytes, so nothing else here would
    notice a Float column creeping back in (issue #533).
    """

    def test_no_column_compiles_to_single_precision(self):
        dialect = mysql.dialect()
        single = []
        for table in db.Base.metadata.sorted_tables:
            for column in table.columns:
                # Only floating point types are compiled: some String columns
                # have no length, which the MySQL compiler refuses outright.
                if not isinstance(column.type, Float):
                    continue
                compiled = column.type.compile(dialect=dialect)
                if compiled.upper().startswith('FLOAT'):
                    single.append('%s.%s' % (table.name, column.name))
        self.assertEqual(
            [], single,
            'these columns are single-precision FLOAT on MySQL and MariaDB; '
            'declare them Double')

    def test_every_time_column_is_double(self):
        dialect = mysql.dialect()
        for table, column in _TIME_COLUMNS:
            compiled = db.Base.metadata.tables[table].columns[column].type.\
                compile(dialect=dialect)
            self.assertEqual('DOUBLE', compiled, '%s.%s' % (table, column))


class MigrationPrecisionTestCase(testtools.TestCase):
    """The migration must widen the existing columns on MySQL.

    Changing the models alone fixes only databases created afresh by
    create_all; every deployed database was built by the migrations, so
    the migrations are what an upgraded deployment actually gets. Rendered
    offline, so no database is needed.
    """

    def test_upgrade_widens_every_time_column_to_double(self):
        sql = _offline_sql('upgrade', 'cdb5c3529858:a8d3f6e1c9b2')
        for table, column in _TIME_COLUMNS:
            self.assertIn(
                'ALTER TABLE %s MODIFY %s DOUBLE NULL' % (table, column), sql)

    def test_downgrade_restores_float(self):
        sql = _offline_sql('downgrade', 'a8d3f6e1c9b2:cdb5c3529858')
        for table, column in _TIME_COLUMNS:
            self.assertIn(
                'ALTER TABLE %s MODIFY %s FLOAT NULL' % (table, column), sql)


class ConsoleKeyMigrationTestCase(testtools.TestCase):
    """consoles is keyed on (source, uuid) after the migration (issue #468)."""

    def test_upgrade_rekeys_consoles_and_their_tokens(self):
        sql = _offline_sql('upgrade', 'a8d3f6e1c9b2:3b8d5f1a6c92')
        self.assertIn(
            'ALTER TABLE consoletokens DROP FOREIGN KEY consoletokens_ibfk_1',
            sql)
        self.assertIn(
            'ALTER TABLE consoles DROP PRIMARY KEY, '
            'ADD PRIMARY KEY (source, uuid)', sql)
        self.assertIn(
            'FOREIGN KEY(source, uuid) REFERENCES consoles (source, uuid) '
            'ON DELETE CASCADE ON UPDATE CASCADE', sql)

    def test_downgrade_restores_the_uuid_key(self):
        sql = _offline_sql('downgrade', '3b8d5f1a6c92:a8d3f6e1c9b2')
        self.assertIn(
            'ALTER TABLE consoletokens DROP FOREIGN KEY '
            'fk_consoletokens_console', sql)
        self.assertIn(
            'ALTER TABLE consoles DROP PRIMARY KEY, ADD PRIMARY KEY (uuid)',
            sql)
        self.assertIn(
            'FOREIGN KEY(uuid) REFERENCES consoles (uuid) '
            'ON DELETE CASCADE ON UPDATE CASCADE', sql)

    def test_model_primary_key_is_source_and_uuid(self):
        self.assertEqual(
            ['source', 'uuid'],
            [c.name for c in db.Console.__table__.primary_key.columns])
