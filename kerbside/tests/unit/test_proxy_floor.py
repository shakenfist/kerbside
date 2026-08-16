import pathlib
import re
import unittest

from packaging.requirements import Requirement
from packaging.version import Version


# The committed kerbside-proxy requirement is the load-bearing detail of the
# rolling dev release design: naming a .dev version in the specifier is what
# opts pip into pre-release resolution, so a git install resolves the newest
# proxy wheel on PyPI (release or rolling dev). Someone tidying the floor to
# a plain `>=X.Y.Z` would silently disable dev-wheel resolution, and the
# failure would only surface downstream as the red Kolla scenario jobs this
# design exists to fix. These tests pin the property in the required unit
# test lane. (At release time tools/stamp-proxy-version.sh replaces the
# floor with an exact ==X.Y.Z pin; these tests only apply to the committed
# tree, which tox always runs from.)


def _committed_proxy_requirement():
    pyproject = pathlib.Path(__file__).parents[3] / 'pyproject.toml'
    lines = re.findall(r'"(kerbside-proxy[^"]*)"', pyproject.read_text())
    return lines


class ProxyFloorTestCase(unittest.TestCase):
    def test_exactly_one_committed_requirement(self):
        self.assertEqual(1, len(_committed_proxy_requirement()))

    def test_floor_admits_dev_wheels_without_prerelease_optin(self):
        # No prereleases= argument: this asserts the pip-relevant behaviour,
        # where only a specifier that itself names a pre-release admits one.
        req = Requirement(_committed_proxy_requirement()[0])
        self.assertTrue(
            req.specifier.contains(Version('0.4.1.dev163')),
            'the committed kerbside-proxy floor no longer admits dev '
            'wheels; it must name a .dev version (e.g. >=0.4.0.dev0)')

    def test_floor_excludes_versions_below_it(self):
        req = Requirement(_committed_proxy_requirement()[0])
        self.assertFalse(req.specifier.contains(Version('0.3.0')))
