import os

import testtools
import yaml

# The workflows are repository data, not package data, so no wheel
# carries them.
from kerbside.tests.unit.test_docs_links import _repo_root


_ROOT = _repo_root()
_WORKFLOW = os.path.join(
    _ROOT, '.github', 'workflows', 'release.yml') if _ROOT else None

# Every job in release.yml is one of these. A job named outside the two
# prefixes has to be classified here before this test will pass, which is
# the point: a new job that builds or publishes an artifact must join a
# set, rather than silently escaping the rules below.
#
#   build*    builds an artifact of the release
#   publish*  sends one somewhere the world can see, and
#             github-release does the same for the GitHub release
_PUBLISHERS = {'github-release'}
_OTHER = {'ci-gate', 'sign-tag'}


def _needs(job):
    """A job's needs, which may be absent, a string or a list."""
    needed = job.get('needs', [])
    if isinstance(needed, str):
        return [needed]
    return list(needed)


def _transitive_needs(jobs, name):
    """Every job that must succeed before this one becomes eligible."""
    seen = set()
    pending = _needs(jobs[name])
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(_needs(jobs[current]))
    return seen


class ReleaseWorkflowTestCase(testtools.TestCase):
    """A release is all-or-nothing, or it is not a release.

    PyPI and Galaxy both refuse a reupload, so a release that publishes
    some of its artifacts and fails on the rest cannot be completed: the
    version has to be burned and the next one cut. sign-tag is the single
    chokepoint every publishing job needs, so gating it on every build is
    what makes the whole set all-or-nothing -- and it was missing
    build-collection, which published both wheels to PyPI while skipping
    Galaxy and the GitHub release (#621).
    """

    def setUp(self):
        super().setUp()
        if _ROOT is None or not os.path.exists(_WORKFLOW):
            self.skipTest('not running from a repository checkout')
        with open(_WORKFLOW) as f:
            self.jobs = yaml.safe_load(f)['jobs']
        self.builds = {name for name in self.jobs
                       if name.startswith('build')}
        self.publishers = {name for name in self.jobs
                           if name.startswith('publish')} | _PUBLISHERS

    def test_every_job_is_classified(self):
        self.assertEqual(
            set(), set(self.jobs) - self.builds - self.publishers - _OTHER,
            'a release job is neither a build, a publisher, nor one of the '
            'jobs listed in _OTHER: classify it there, and say which of the '
            'rules in this file it is meant to obey')

    def test_the_release_builds_and_publishes_several_things(self):
        # Floors, so that a rename which empties a set cannot make the
        # assertions below vacuously true.
        self.assertGreaterEqual(len(self.builds), 3)
        self.assertGreaterEqual(len(self.publishers), 3)

    def test_signing_waits_for_every_build(self):
        self.assertEqual(
            set(), self.builds - _transitive_needs(self.jobs, 'sign-tag'),
            'sign-tag does not wait for every job that builds a release '
            'artifact, so a failed build can leave signing eligible')

    def test_nothing_publishes_before_every_build_has_succeeded(self):
        for name in sorted(self.publishers):
            missing = self.builds - _transitive_needs(self.jobs, name)
            self.assertEqual(
                set(), missing,
                '%s can publish without %s having succeeded, so a failure '
                'there leaves a partial release' % (name, sorted(missing)))

    def test_nothing_publishes_an_unsigned_release(self):
        for name in sorted(self.publishers):
            self.assertIn(
                'sign-tag', _transitive_needs(self.jobs, name),
                '%s does not need sign-tag' % name)
