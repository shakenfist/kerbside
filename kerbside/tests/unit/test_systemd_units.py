import os

import jinja2
import testtools
import yaml

# The role and etc/ are repository data, not package data, so no wheel
# carries them.
from kerbside.tests.unit.test_docs_links import _repo_root


_ROOT = _repo_root()
_ROLE = os.path.join(_ROOT, 'ansible', 'roles', 'kerbside') if _ROOT else None

# The example units in etc/systemd/ are the role's templates rendered with
# the role's defaults. These are the only deliberate differences, each with
# the reason for it, so that a new one cannot be added quietly.
OVERRIDES = {
    # The role binds the API to every interface. A file operators copy
    # verbatim should be safe when copied verbatim: the API carries bearer
    # tokens and Keystone credentials in plain HTTP, so the example binds to
    # loopback and expects TLS in front of it. See docs/deployment/manual.md.
    'kerbside_api_address': '127.0.0.1',
}

UNITS = ('kerbside-api.service', 'kerbside-daemon.service')


def _render(name, overrides):
    with open(os.path.join(_ROLE, 'defaults', 'main.yml')) as f:
        variables = yaml.safe_load(f)
    variables.update(overrides)
    # A variable from outside defaults/main.yml, such as one the role sets
    # in a task, fails the render here rather than rendering empty.
    env = jinja2.Environment(
        keep_trailing_newline=True, undefined=jinja2.StrictUndefined,
        loader=jinja2.FileSystemLoader(os.path.join(_ROLE, 'templates')))
    return env.get_template(name).render(variables)


def _directives(text):
    """Return (section, directive line) pairs, in order.

    Comments and blank lines are ignored. A directive which appears more
    than once in a section, such as Environment=, yields one pair each time.
    """
    pairs = []
    section = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            continue
        pairs.append((section, line))
    return pairs


def _first_difference(expected, actual):
    for i in range(max(len(expected), len(actual))):
        want = expected[i] if i < len(expected) else None
        got = actual[i] if i < len(actual) else None
        if want != got:
            return ('directive %d: role template renders %r, example has %r'
                    % (i, want, got))
    return None


class SystemdUnitTestCase(testtools.TestCase):
    """The example units are the role's templates, rendered."""

    def setUp(self):
        super().setUp()
        if _ROOT is None or not os.path.isdir(_ROLE):
            self.skipTest('not running from a repository checkout')

    def _example(self, name):
        with open(os.path.join(_ROOT, 'etc', 'systemd', name)) as f:
            return f.read()

    def test_override_dict_has_one_key(self):
        self.assertEqual(['kerbside_api_address'], list(OVERRIDES))

    def test_examples_match_templates(self):
        for name in UNITS:
            # The daemon template uses none of the overridden values, so
            # this also shows the override changes nothing else.
            expected = _directives(_render(name, OVERRIDES))
            actual = _directives(self._example(name))
            self.assertIsNone(
                _first_difference(expected, actual),
                '%s has drifted from the role template' % name)

    def test_api_binds_loopback(self):
        self.assertIn(' --bind 127.0.0.1:13002 ',
                      self._example('kerbside-api.service'))

    def test_comparison_detects_a_changed_directive(self):
        for name in UNITS:
            expected = _directives(_render(name, OVERRIDES))
            lines = self._example(name).splitlines()
            index = [i for i, line in enumerate(lines)
                     if line.startswith('RestartSec=')][0]
            lines[index] = 'RestartSec=6'
            actual = _directives('\n'.join(lines))
            self.assertIsNotNone(_first_difference(expected, actual), name)

    def test_comparison_detects_a_moved_section(self):
        # The same line under a different section must not compare equal.
        name = 'kerbside-daemon.service'
        expected = _directives(_render(name, OVERRIDES))
        wanted = 'WantedBy=multi-user.target\n'
        text = self._example(name).replace('[Install]\n' + wanted, '')
        text = text.replace('[Service]\n', '[Service]\n' + wanted, 1)
        self.assertIsNotNone(_first_difference(expected, _directives(text)))

    def test_repeated_directive_is_kept(self):
        text = '[Service]\nEnvironment=A=1\nEnvironment=B=2\n'
        self.assertEqual(
            [('Service', 'Environment=A=1'), ('Service', 'Environment=B=2')],
            _directives(text))
