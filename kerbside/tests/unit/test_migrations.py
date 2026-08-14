import configparser
import importlib.resources
import os
from unittest import mock

from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from click.testing import CliRunner
import testtools

from kerbside import main


# The revisions present when the migration tree was moved into the
# package. New migrations push the count up, so this is a floor rather
# than an equality -- the point is that the versions directory is not
# empty or partially shipped, not that it is frozen.
_KNOWN_REVISION_COUNT = 9


class PackagedMigrationsTestCase(testtools.TestCase):
    """The migration tree must live inside the package.

    It did not, before this was written. pyproject.toml names only the
    kerbside and kerbside.rpc packages, and everything else that ships
    (kerbside/api/, kerbside/sources/) does so because setuptools_scm's
    git file-finder contributes tracked files found *beneath a package
    directory*. The migrations lived in a top-level alembic/ directory,
    outside the package, so no built artifact contained them and
    `pip install kerbside` could not create its own schema.

    SCOPE, and it is narrower than it looks: these are LAYOUT tests, not
    wheel-content tests. .stestr.conf sets top_dir=./, so unittest
    discovery puts the repository root on sys.path and
    importlib.resources.files('kerbside') resolves to ./kerbside in the
    checkout -- never to whatever tox installed. So they catch the tree
    being moved back out of the package, and they catch the packaged
    alembic.ini becoming unloadable, but they are blind to anything that
    drops the files from the built artifact: an exclude-package-data
    entry, include-package-data being turned off, a build-backend change.

    That regression class is covered instead by tools/check-wheel.py,
    which builds a wheel and inspects it, and runs in the sanity_checks
    CI job. Do not extend this file to claim wheel coverage; extend that
    script.
    """

    def _migrations(self):
        return importlib.resources.files('kerbside') / 'migrations'

    def test_migration_environment_is_packaged(self):
        migrations = self._migrations()
        for name in ('alembic.ini', 'env.py', 'script.py.mako'):
            self.assertTrue(
                (migrations / name).is_file(),
                'kerbside/migrations/%s is missing from the package' % name)

    def test_revisions_are_packaged(self):
        versions = self._migrations() / 'versions'
        revisions = [f for f in versions.iterdir()
                     if f.name.endswith('.py')]
        self.assertGreaterEqual(
            len(revisions), _KNOWN_REVISION_COUNT,
            'expected at least %d packaged revisions, found %d'
            % (_KNOWN_REVISION_COUNT, len(revisions)))

    def test_packaged_config_resolves_the_script_directory(self):
        """The assertion that actually matters.

        Files being present is necessary but not sufficient: what
        `kerbside db upgrade` depends on is alembic being able to load
        the packaged ini and walk the revisions from it. This exercises
        that resolution without touching a database, so it runs in the
        unit suite.
        """
        migrations = self._migrations()
        config = AlembicConfig(str(migrations / 'alembic.ini'))
        config.set_main_option('script_location', str(migrations))

        script_directory = ScriptDirectory.from_config(config)
        revisions = list(script_directory.walk_revisions())

        self.assertGreaterEqual(len(revisions), _KNOWN_REVISION_COUNT)
        self.assertIsNotNone(script_directory.get_current_head())

    def test_packaged_config_does_not_prepend_sys_path(self):
        """The packaged ini must not carry prepend_sys_path.

        alembic's ScriptDirectory.from_config() honours the setting, so
        a value of '.' would put the caller's current working directory
        on sys.path every time `kerbside db upgrade` runs -- meaning a
        stray os.py or yaml.py in an operator's cwd becomes importable.
        The developer copy at the repository root keeps the setting,
        because env.py needs it to import kerbside from a checkout.
        """
        parser = configparser.ConfigParser()
        parser.read_string(
            (self._migrations() / 'alembic.ini').read_text())

        self.assertNotIn(
            'prepend_sys_path', parser['alembic'],
            'the packaged alembic.ini must not set prepend_sys_path; see '
            'the comment in that file')

    def _repository_root(self):
        """Walk up to the directory holding the developer alembic.ini."""
        path = os.path.dirname(os.path.abspath(__file__))
        while path != '/':
            if os.path.isfile(os.path.join(path, 'alembic.ini')):
                return path
            path = os.path.dirname(path)
        return None

    def test_root_config_agrees_with_the_packaged_one(self):
        """The developer alembic.ini must still resolve, and to the same head.

        Nothing else exercises it any more. Before this phase,
        start-kerbside.sh ran `alembic upgrade head` from the repository
        root on every direct-qemu run, which incidentally validated the
        root ini; that call is now `kerbside db upgrade`, which loads the
        packaged copy and overrides script_location. So a typo'd or stale
        root script_location would merge green and surface as a broken
        `alembic revision` for the next person adding a migration.

        Asserting both copies enumerate the same head also pins them to
        one revision graph, which is what the anti-drift comments in the
        two files ask for.
        """
        root = self._repository_root()
        if root is None:
            # An installed wheel has no root alembic.ini. Skip rather than
            # fail, so the suite is runnable from site-packages.
            raise testtools.TestCase.skipException(
                'no repository-root alembic.ini; not running from a checkout')

        root_config = AlembicConfig(os.path.join(root, 'alembic.ini'))
        # script_location in that file is relative to the repository root.
        root_config.set_main_option(
            'script_location',
            os.path.join(root, root_config.get_main_option('script_location')))
        root_head = ScriptDirectory.from_config(root_config).get_current_head()

        packaged = self._migrations()
        packaged_config = AlembicConfig(str(packaged / 'alembic.ini'))
        packaged_config.set_main_option('script_location', str(packaged))
        packaged_head = ScriptDirectory.from_config(
            packaged_config).get_current_head()

        self.assertEqual(root_head, packaged_head)


class DbCommandTestCase(testtools.TestCase):
    """Contract tests for the `kerbside db` group.

    The commands are thin wrappers, but two of their properties are
    deliberate decisions rather than accidents, and neither is asserted
    anywhere else: downgrade refuses to run without an explicit target,
    and both resolve the migrations from the packaged directory rather
    than from the caller's working directory.
    """

    def setUp(self):
        super().setUp()
        self.runner = CliRunner()

    def test_downgrade_requires_an_explicit_revision(self):
        """A downgrade with an implied target is a foot-gun.

        Guards against someone later adding default='head' here by
        symmetry with upgrade, which would silently make `kerbside db
        downgrade` runnable against a production database.
        """
        result = self.runner.invoke(main.db, ['downgrade'])

        self.assertNotEqual(0, result.exit_code)
        self.assertIn('--revision', result.output)

    def test_upgrade_targets_head_by_default(self):
        with mock.patch('kerbside.main.alembic_command') as mock_alembic:
            result = self.runner.invoke(main.db, ['upgrade'])

        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(1, mock_alembic.upgrade.call_count)
        self.assertEqual('head', mock_alembic.upgrade.call_args[0][1])

    def test_upgrade_passes_an_explicit_revision_through(self):
        with mock.patch('kerbside.main.alembic_command') as mock_alembic:
            result = self.runner.invoke(
                main.db, ['upgrade', '--revision', 'ad47e96baff6'])

        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual('ad47e96baff6', mock_alembic.upgrade.call_args[0][1])

    def test_a_failing_migration_exits_non_zero_without_a_traceback(self):
        with mock.patch('kerbside.main.alembic_command') as mock_alembic:
            mock_alembic.upgrade.side_effect = RuntimeError('database on fire')
            result = self.runner.invoke(main.db, ['upgrade'])

        self.assertNotEqual(0, result.exit_code)
        self.assertIn('Database upgrade failed', result.output)
        self.assertNotIn('Traceback', result.output)

    def test_config_points_at_the_packaged_migrations(self):
        config = main._alembic_config()

        script_location = config.get_main_option('script_location')
        self.assertTrue(
            script_location.endswith(os.path.join('kerbside', 'migrations')),
            'script_location should resolve to the packaged directory, got %s'
            % script_location)


class MigrationUrlEscapingTestCase(testtools.TestCase):
    """env.py must escape percent signs in SQL_URL.

    set_main_option() hands the value to ConfigParser.set() with pyformat
    interpolation active, so a bare % raises ValueError before the
    migration starts. An operator who percent-encodes '@', '/', '#' or
    '!' in a database password hits it on every migration run, and this
    phase is what turns migrations into the documented operator path.
    """

    def test_a_percent_bearing_url_survives_set_main_option(self):
        url = 'mysql+pymysql://kerbside:p%40ssw0rd@db/kerbside'

        config = AlembicConfig()
        config.set_main_option('sqlalchemy.url', url.replace('%', '%%'))

        self.assertEqual(url, config.get_main_option('sqlalchemy.url'))

    def test_an_unescaped_percent_would_have_failed(self):
        """Pin the reason the escaping exists, not just its effect."""
        config = AlembicConfig()

        self.assertRaises(
            ValueError, config.set_main_option, 'sqlalchemy.url',
            'mysql+pymysql://kerbside:p%40ssw0rd@db/kerbside')
