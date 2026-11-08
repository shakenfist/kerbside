import os
import re

import testtools
import yaml

# The workflows are repository data, not package data, so no wheel
# carries them.
from kerbside.tests.unit.test_docs_links import _repo_root


_ROOT = _repo_root()
_WORKFLOW = os.path.join(
    _ROOT, '.github', 'workflows', 'functional-tests.yml') if _ROOT else None

_JOB = 'nightly_failure_issue'
_SCRIPT = 'tools/file-nightly-failure-issue.sh'

# One clause of a step's if:, which is all this job's guards use.
_CLAUSE = re.compile(
    r"^needs\.(?P<job>[a-z_]+)\.result\s*(?P<op>==|!=)\s*'(?P<value>\w+)'$")


def _evaluate(expression, results):
    """Is this step's if: true, given each needed job's result?

    Only the shape this job's guards use: needs.<job>.result compared
    against a literal, joined by &&. Anything else raises rather than
    quietly evaluating to something.

    A reference to a job that is not in the needs list evaluates to None
    in GitHub Actions, so `!= 'success'` is true and `== 'success'` is
    false -- which is modelled here rather than treated as an error,
    because silently wrong is exactly what it does in production.
    """
    for clause in expression.split('&&'):
        match = _CLAUSE.match(' '.join(clause.split()))
        if not match:
            raise ValueError('unsupported guard clause: %r' % clause)
        actual = results.get(match.group('job'))
        equal = actual == match.group('value')
        if equal != (match.group('op') == '=='):
            return False
    return True


class NightlyFailureIssueTestCase(testtools.TestCase):
    """A nightly failure is filed under the job that broke.

    Both cloud matrices need sanity_checks and check_paths, so a failure
    in either skips both. The job reported every needed job that had not
    succeeded, which meant a sanity_checks failure filed the oVirt and
    OpenStack issues -- naming two lanes that had not run, and leaving
    the one that broke unnamed (#626).
    """

    def setUp(self):
        super().setUp()
        if _ROOT is None or not os.path.exists(_WORKFLOW):
            self.skipTest('not running from a repository checkout')
        with open(_WORKFLOW) as f:
            self.job = yaml.safe_load(f)['jobs'][_JOB]
        self.steps = [s for s in self.job['steps'] if _SCRIPT in s.get('run', '')]

    def _lane(self, step):
        """The lane name a step passes to the filing script."""
        after = step['run'].split(_SCRIPT, 1)[1].split()
        return after[0]

    def _filed(self, **results):
        """The lanes filed, given these job results."""
        return {self._lane(step) for step in self.steps
                if _evaluate(step['if'], results)}

    def test_every_job_a_guard_names_is_in_needs(self):
        """A guard on a job outside needs: is silently always true.

        needs.<absent>.result is None, so `!= 'success'` fires and the
        step runs on every failure of anything -- the same class of
        defect as #626, with no symptom until it misfiles.
        """
        needed = set(self.job['needs'])
        self.assertTrue(needed)
        for step in self.steps:
            for clause in step['if'].split('&&'):
                job = _CLAUSE.match(' '.join(clause.split())).group('job')
                self.assertIn(job, needed, step['name'])

    def test_each_lane_is_filed_once_at_most(self):
        lanes = [self._lane(step) for step in self.steps]
        self.assertEqual(sorted(set(lanes)), sorted(lanes))
        # And the lanes the two cloud matrices are named for are among
        # them, so the scenarios below are not asserting about nothing.
        self.assertIn('oVirt', lanes)
        self.assertIn('OpenStack', lanes)

    def test_a_sanity_checks_failure_is_filed_as_sanity_checks(self):
        # This is the reported defect: both matrices skip, and neither
        # had run, so neither is what broke.
        self.assertEqual(
            {'sanity-checks'},
            self._filed(check_paths='success', sanity_checks='failure',
                        ovirt_matrix='skipped', openstack_matrix='skipped'))

    def test_a_check_paths_failure_is_filed_as_check_paths(self):
        # The same shape one job further up: everything downstream skips.
        self.assertEqual(
            {'check-paths'},
            self._filed(check_paths='failure', sanity_checks='skipped',
                        ovirt_matrix='skipped', openstack_matrix='skipped'))

    def test_a_failing_cloud_lane_is_filed_as_itself(self):
        self.assertEqual(
            {'oVirt'},
            self._filed(check_paths='success', sanity_checks='success',
                        ovirt_matrix='failure', openstack_matrix='success'))
        self.assertEqual(
            {'OpenStack'},
            self._filed(check_paths='success', sanity_checks='success',
                        ovirt_matrix='success', openstack_matrix='failure'))

    def test_both_cloud_lanes_failing_files_both(self):
        self.assertEqual(
            {'oVirt', 'OpenStack'},
            self._filed(check_paths='success', sanity_checks='success',
                        ovirt_matrix='failure', openstack_matrix='failure'))

    def test_an_all_green_run_files_nothing(self):
        self.assertEqual(
            set(),
            self._filed(check_paths='success', sanity_checks='success',
                        ovirt_matrix='success', openstack_matrix='success'))
