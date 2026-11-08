import ast
import re
from pathlib import Path

import testtools


# The sf-e2e lane's helpers live in tools/sf-e2e/ (outside the importable
# package) and import shakenfist_client, which is not a test dependency, so
# they are read and parsed rather than imported. These are static contract
# tests: they assert how the lane's scripts fit together, which no unit test
# could otherwise reach and only a 90-minute lane run would otherwise catch.
_TOOLS = Path(__file__).resolve().parents[3] / 'tools' / 'sf-e2e'

_DRIVERS = ('drive-adversarial.py', 'drive-happy-path.py')


def _source(filename):
    return (_TOOLS / filename).read_text()


def _env_reads(filename):
    """Every name the script requires as os.environ['NAME'].

    Only loads count. os.environ.get(...) is excluded because those have
    defaults, and an assignment (the drivers set no_proxy) is the script
    supplying a name rather than demanding one.
    """
    names = set()
    for node in ast.walk(ast.parse(_source(filename))):
        if (isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Load)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == 'environ'
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)):
            names.add(node.slice.value)
    return names


def _prepare_drivers_writes():
    """The names prepare-drivers.sh puts in kerbside.env.

    Its embedded python builds the file from a list of ('NAME', value)
    tuples, which is matched here rather than executed.
    """
    source = _source('prepare-drivers.sh')
    env_block = re.search(r'\nenv = \[\n(.*?)\n\]\n', source, re.DOTALL)
    assert env_block, 'prepare-drivers.sh no longer builds an "env = [...]" list'
    return set(re.findall(r"\('([A-Z0-9_]+)',", env_block.group(1)))


def _import_instance_writes():
    """The names import-instance.sh puts in instance.env."""
    source = _source('import-instance.sh')
    return set(re.findall(r"f\.write\('([A-Z0-9_]+)=", source))


class SfE2eEnvContractTestCase(testtools.TestCase):
    def test_every_name_a_driver_reads_is_written(self):
        """No driver may read an env name no script in the lane writes.

        The two env files are the whole interface between the setup scripts
        and the drivers, so a driver reading a name nobody writes is a
        KeyError 90 minutes into the lane.
        """
        written = _prepare_drivers_writes() | _import_instance_writes()
        for driver in _DRIVERS:
            missing = _env_reads(driver) - written
            self.assertEqual(
                set(), missing,
                '%s reads env names neither prepare-drivers.sh nor '
                'import-instance.sh writes: %s'
                % (driver, ', '.join(sorted(missing))))

    def test_import_instance_writes_both_namespace_fixtures(self):
        """Both namespaces the lane needs come from import-instance.sh.

        Creating a namespace needs the cluster's deploy key from
        /etc/sf/sfrc, which only this script has, so both fixtures are made
        here and handed to the drivers as ordinary namespace keys.
        """
        written = _import_instance_writes()
        for name in ('SF_NAMESPACE', 'SF_NAMESPACE_KEY',
                     'SF_OTHER_NAMESPACE', 'SF_OTHER_NAMESPACE_KEY'):
            self.assertIn(name, written)


class SfE2eCredentialTestCase(testtools.TestCase):
    """Guards kerbside#697: the drivers hold no system-namespace credential.

    Shaken Fist's deploy mints the "kerbside" scrape key read-only
    (shakenfist/shakenfist#4698), so a driver which borrows it to create a
    namespace gets a 403. Nothing stops that being reintroduced except these
    assertions -- the lane itself only notices after a full deploy.
    """

    def test_no_driver_authenticates_as_the_system_namespace(self):
        for driver in _DRIVERS:
            for node in ast.walk(ast.parse(_source(driver))):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg != 'namespace':
                        continue
                    if (isinstance(kw.value, ast.Constant)
                            and kw.value.value == 'system'):
                        self.fail(
                            "%s builds a client with namespace='system' on "
                            'line %d. The drivers are handed namespace keys '
                            'only; namespace fixtures belong in '
                            'import-instance.sh (kerbside#697).'
                            % (driver, node.lineno))

    def test_no_driver_reads_the_scrape_credential(self):
        """sources.yaml holds the read-only "kerbside" key as a password."""
        for driver in _DRIVERS:
            self.assertNotIn(
                'KERBSIDE_SOURCES_PATH', _env_reads(driver),
                '%s reads sources.yaml, whose shakenfist source password is '
                'the read-only scrape key (kerbside#697).' % driver)

    def test_no_driver_writes_namespaces(self):
        """Namespace creation needs scopes the drivers' keys cannot hold."""
        forbidden = ('create_namespace', 'delete_namespace',
                     'add_namespace_key')
        for driver in _DRIVERS:
            for node in ast.walk(ast.parse(_source(driver))):
                if (isinstance(node, ast.Attribute)
                        and node.attr in forbidden):
                    self.fail(
                        '%s calls %s on line %d; namespace fixtures belong '
                        'in import-instance.sh, which holds the deploy key '
                        '(kerbside#697).' % (driver, node.attr, node.lineno))
