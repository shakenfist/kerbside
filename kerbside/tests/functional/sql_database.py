"""A scratch database on a real MariaDB or MySQL server, for functional tests.

The tests which need one are skipped unless KERBSIDE_TEST_SQL_URL names it.
The database is dropped and recreated, and dropped again at the end, so its
name must end in 'test'. The user needs every privilege on that database,
including CREATE and DROP. The schema is created by running the migrations
to head, as `kerbside db upgrade` does in production, so the tests also
prove that the migrations apply to a real engine.

This uses only kerbside's runtime dependencies and the standard library, so
that the tests run where only those are installed.
"""

import os
from unittest import mock

from alembic import command as alembic_command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from kerbside.config import config
from kerbside import main


TEST_SQL_URL = os.environ.get('KERBSIDE_TEST_SQL_URL')


def _server_engine(url):
    """Return an engine on the same server which does not use url's database.

    information_schema exists on every server and every user may use it.
    URL.set() treats database=None as leaving the database unchanged, so it
    cannot be used to remove one.
    """
    return create_engine(url.set(database='information_schema'),
                         hide_parameters=True)


def drop_database(url):
    server = _server_engine(url)
    try:
        with server.connect() as conn:
            conn.execute(text('DROP DATABASE IF EXISTS `%s`' % url.database))
    finally:
        server.dispose()


def migrated_database():
    """Recreate the database TEST_SQL_URL names, and migrate it to head.

    Returns the database's URL. Raises RuntimeError, before touching the
    server, if the database's name does not end in 'test'.
    """
    url = make_url(TEST_SQL_URL)
    if not url.database or not url.database.endswith('test'):
        raise RuntimeError(
            'KERBSIDE_TEST_SQL_URL must name a database ending in "test", '
            'because these tests drop and recreate it')

    drop_database(url)
    server = _server_engine(url)
    try:
        with server.connect() as conn:
            conn.execute(text('CREATE DATABASE `%s`' % url.database))
    finally:
        server.dispose()

    with mock.patch.object(
            config, 'SQL_URL', url.render_as_string(hide_password=False)):
        alembic_command.upgrade(main._alembic_config(), 'head')
    return url
