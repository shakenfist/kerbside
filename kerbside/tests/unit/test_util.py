import ast
import io
import pathlib

import testtools
import yaml

from kerbside import util


_PACKAGE = pathlib.Path(util.__file__).parent
_PARSERS = ('load', 'safe_load', 'load_all', 'safe_load_all', 'full_load',
            'unsafe_load')


class LoadSourcesTestCase(testtools.TestCase):
    """util.load_sources() keeps numbers as the text they spell."""

    def test_numbers_and_dates_are_text(self):
        loaded = util.load_sources(io.StringIO(
            '[012345, 0x1F, 1_000, "12:34", 12:34, 1.10, 2026-10-08, 7]'))
        self.assertEqual(
            ['012345', '0x1F', '1_000', '12:34', '12:34', '1.10',
             '2026-10-08', '7'], loaded)

    def test_booleans_and_null_keep_their_types(self):
        # verify: and synthesize_host_subject: are booleans, and an
        # optional field written as null is absent.
        self.assertEqual([True, False, None],
                         util.load_sources(io.StringIO('[true, false, null]')))

    def test_safe_load_is_unchanged(self):
        # The resolver table is copied, not edited: everything else in
        # the process that parses YAML still gets YAML 1.1 types.
        util.load_sources(io.StringIO('[1]'))
        self.assertEqual([5349, 31], yaml.safe_load('[012345, 0x1F]'))


class OneReaderTestCase(testtools.TestCase):
    """Nothing in the package parses YAML except util.load_sources().

    sources.yaml is read in five places. One which used yaml.safe_load()
    would quietly turn a ticket written as 012345 into '5349' again, so
    the parse is kept in one function and this holds it there.
    """

    def test_no_other_yaml_parse(self):
        offenders = []
        for path in sorted(_PACKAGE.rglob('*.py')):
            relative = path.relative_to(_PACKAGE)
            if relative.parts[0] == 'tests' or relative == pathlib.Path('util.py'):
                continue
            for node in ast.walk(ast.parse(path.read_text(), str(path))):
                if (isinstance(node, ast.Attribute)
                        and isinstance(node.value, ast.Name)
                        and node.value.id == 'yaml'
                        and node.attr in _PARSERS):
                    offenders.append('%s:%d yaml.%s'
                                     % (relative, node.lineno, node.attr))
                elif (isinstance(node, ast.ImportFrom)
                        and node.module == 'yaml'
                        and any(a.name in _PARSERS for a in node.names)):
                    offenders.append('%s:%d from yaml import'
                                     % (relative, node.lineno))
        self.assertEqual([], offenders)


class YAMLPortTestCase(testtools.TestCase):

    def test_accepts(self):
        for value, port in (('1', 1), ('5910', 5910), ('65535', 65535),
                            (5910, 5910)):
            self.assertEqual(port, util.yaml_port(value))

    def test_refuses_without_quoting_the_value(self):
        for value in ('0', '-1', '65536', '70000', '²', '٥٩',
                      '5910.0', ' 5910', '', 0, -1, 70000, True, None,
                      5910.0, ['5910']):
            e = self.assertRaises(util.YAMLScalarError, util.yaml_port, value)
            if isinstance(value, str) and value:
                self.assertNotIn(value, str(e))


class YAMLStringTestCase(testtools.TestCase):

    def test_accepts_text(self):
        self.assertEqual('012345', util.yaml_string('012345'))

    def test_refuses_everything_else(self):
        for value in (12345, True, None, 1.5, ['hunter2'], {'hunter2': 1}):
            e = self.assertRaises(util.YAMLScalarError, util.yaml_string,
                                  value)
            self.assertNotIn('hunter2', str(e))
