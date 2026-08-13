import configparser
import importlib.resources

from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
import testtools


# The revisions present when the migration tree was moved into the
# package. New migrations push the count up, so this is a floor rather
# than an equality -- the point is that the versions directory is not
# empty or partially shipped, not that it is frozen.
_KNOWN_REVISION_COUNT = 9


class PackagedMigrationsTestCase(testtools.TestCase):
    """The migration tree must ship inside the wheel.

    It did not, before this was written. pyproject.toml names only the
    kerbside and kerbside.rpc packages, and everything else that ships
    (kerbside/api/, kerbside/sources/) does so because setuptools_scm's
    git file-finder contributes tracked files found *beneath a package
    directory*. The migrations lived in a top-level alembic/ directory,
    outside the package, so no built artifact contained them and
    `pip install kerbside` could not create its own schema.

    These tests fail if the tree moves back out of the package, or if
    the packaged alembic.ini stops being loadable -- which is the
    failure that would otherwise only show up for someone installing
    from PyPI, never for a developer working in a checkout.
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
