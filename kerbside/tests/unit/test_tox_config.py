import configparser
import os

import testtools

# tox.ini is repository data, not package data, so no wheel carries it.
from kerbside.tests.unit.test_docs_links import _repo_root


_ROOT = _repo_root()

# Without this, shakenfist_utilities.logs.setup() installs a
# SysLogHandler('/dev/log') and the unit tests' own logging lands in the
# CI runner's journal, which sfcbr ships to Loki, instead of in the
# stdout stestr captures (#646).
REQUIRED = ('SHAKENFIST_LOG_TO_STDOUT', '1')


def _setenv(parser, section):
    """The effective setenv of a section, as tox resolves it.

    tox does not merge a section's setenv with [testenv]'s: a section
    declaring its own replaces the base wholesale unless it interpolates
    {[testenv]setenv}. That interpolation is what this expands, and
    missing it is the defect #646 reported.
    """
    if not parser.has_option(section, 'setenv'):
        # No setenv of its own: tox gives it [testenv]'s unchanged.
        return _setenv(parser, 'testenv')

    pairs = {}
    for line in parser.get(section, 'setenv').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line == '{[testenv]setenv}':
            pairs.update(_setenv(parser, 'testenv'))
            continue
        name, _, value = line.partition('=')
        pairs[name.strip()] = value.strip()
    return pairs


class ToxSetenvTestCase(testtools.TestCase):
    """Every tox environment sends its logging to stdout.

    A testenv which declares its own setenv silently loses the base
    section's, so this checks each one rather than only [testenv]. The
    cover env had exactly that bug: it replaced the base setenv and so
    ran without SHAKENFIST_LOG_TO_STDOUT, LANGUAGE or the OS_* capture
    and timeout settings.
    """

    def setUp(self):
        super().setUp()
        if _ROOT is None or not os.path.exists(os.path.join(_ROOT, 'tox.ini')):
            self.skipTest('not running from a repository checkout')
        self.parser = configparser.ConfigParser()
        self.parser.read(os.path.join(_ROOT, 'tox.ini'))

    def _sections(self):
        sections = [s for s in self.parser.sections()
                    if s == 'testenv' or s.startswith('testenv:')]
        # A rename of [testenv] would otherwise make this test vacuous.
        self.assertIn('testenv', sections)
        self.assertIn('testenv:cover', sections)
        return sections

    def test_every_testenv_logs_to_stdout(self):
        name, value = REQUIRED
        for section in self._sections():
            self.assertEqual(
                value, _setenv(self.parser, section).get(name),
                '[%s] does not set %s=%s. A section with its own setenv '
                'must interpolate {[testenv]setenv} to keep the base '
                'values.' % (section, name, value))

    def test_every_testenv_keeps_the_base_setenv(self):
        base = _setenv(self.parser, 'testenv')
        for section in self._sections():
            effective = _setenv(self.parser, section)
            for name in base:
                self.assertIn(
                    name, effective,
                    '[%s] drops %s from [testenv]setenv.' % (section, name))
