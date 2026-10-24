import io
from unittest import mock

from alembic import command as alembic_command

from kerbside import main
from kerbside.config import config


def offline_sql(direction, revisions):
    """Render a migration range as MySQL, with no database needed.

    The initial schema cannot be created on SQLite, so a migration is
    tested by asserting the SQL it would run against MySQL or MariaDB.
    """
    cfg = main._alembic_config()
    buffer = io.StringIO()
    cfg.output_buffer = buffer
    with mock.patch.object(
            config, 'SQL_URL', 'mysql://kerbside:pw@db/kerbside'):
        getattr(alembic_command, direction)(cfg, revisions, sql=True)
    return buffer.getvalue()
