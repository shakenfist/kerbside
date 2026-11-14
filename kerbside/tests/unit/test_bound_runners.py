import importlib.util
import shutil
import tempfile
from pathlib import Path

import testtools


# check-bound-runners.py lives in tools/ (outside the importable package) and
# its filename contains a hyphen, so load it as a module by path.
_ROOT = Path(__file__).resolve().parents[3]
_CHECK_BOUND_RUNNERS_PATH = _ROOT / 'tools' / 'check-bound-runners.py'
_spec = importlib.util.spec_from_file_location(
    'check_bound_runners', _CHECK_BOUND_RUNNERS_PATH)
check_bound_runners = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_bound_runners)


BOUND = ('[self-hosted, bound-debian-13, bound-l, '
         '"bind-${{ github.run_id }}-${{ github.run_attempt }}-lane"]')

ACTIONLINT = """
self-hosted-runner:
  labels:
    - vm
    - debian-13
    - l
    - bound-debian-13
    - bound-l
"""


class BoundRunnerFixtureCase(testtools.TestCase):
    """Drive the checks over workflow fixtures.

    Each test breaks the bound-runner invariant one way and asserts the
    breakage is reported. Every one of these failures presents at run
    time as a job queued with no runner and no red check, which is why
    they are worth catching here instead.
    """

    def setUp(self):
        super().setUp()
        self.tree = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tree)
        self.workflows = self.tree / 'workflows'
        self.workflows.mkdir()
        self.actionlint = self.tree / 'actionlint.yaml'
        self.actionlint.write_text(ACTIONLINT)

    def _workflow(self, name, body):
        (self.workflows / name).write_text(body)

    def _check(self):
        return check_bound_runners.check(self.workflows, self.actionlint)

    def test_a_bound_job_alone_is_clean(self):
        self._workflow('a.yml', 'jobs:\n  lane:\n    runs-on: %s\n' % BOUND)
        self.assertEqual([], self._check())

    def test_a_pool_job_beside_a_bound_job_is_clean(self):
        self._workflow('a.yml',
                       'jobs:\n  lane:\n    runs-on: %s\n'
                       '  pool:\n'
                       '    runs-on: [self-hosted, vm, debian-13, l]\n'
                       % BOUND)
        self.assertEqual([], self._check())

    def test_a_bare_self_hosted_job_steals_the_runner(self):
        self._workflow('a.yml',
                       'jobs:\n  lane:\n    runs-on: %s\n'
                       '  thief:\n    runs-on: [self-hosted]\n' % BOUND)
        problems = self._check()
        self.assertEqual(1, len(problems), problems)
        self.assertIn('a.yml:thief', problems[0])
        self.assertIn('subset of bound job', problems[0])

    def test_a_forgotten_bind_token_steals_every_runner(self):
        self._workflow('a.yml',
                       'jobs:\n  lane:\n    runs-on: %s\n'
                       '  copied:\n'
                       '    runs-on: [self-hosted, bound-debian-13, bound-l]\n'
                       % BOUND)
        problems = self._check()
        self.assertIn('exactly one bind- label, not 0',
                      '\n'.join(problems))
        self.assertIn('subset of bound job', '\n'.join(problems))

    def test_an_undeclared_bound_label_is_reported(self):
        self._workflow('a.yml',
                       'jobs:\n  lane:\n'
                       '    runs-on: [self-hosted, bound-debian-13, bound-xl,'
                       ' "bind-${{ github.run_id }}-'
                       '${{ github.run_attempt }}-lane"]\n')
        problems = self._check()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("'bound-xl' is not declared", problems[0])

    def test_the_job_id_makes_a_token_the_provisioner_rejects(self):
        # github.job is the obvious structural disambiguator and it does
        # not work: job ids carry underscores, which the provisioner's
        # token grammar rejects, and a malformed binding gets no runner
        # at all.
        self._workflow('a.yml',
                       'jobs:\n  ovirt_matrix:\n'
                       '    runs-on: [self-hosted, bound-debian-13, bound-l,'
                       ' "bind-${{ github.run_id }}-'
                       '${{ github.run_attempt }}-${{ github.job }}"]\n')
        problems = self._check()
        self.assertEqual(1, len(problems), problems)
        self.assertIn('bind-1-1-ovirt_matrix', problems[0])
        self.assertIn('lowercase slug', problems[0])

    def test_two_bound_jobs_sharing_a_token_collide(self):
        self._workflow('a.yml',
                       'jobs:\n  one:\n    runs-on: %s\n'
                       '  two:\n    runs-on: %s\n' % (BOUND, BOUND))
        problems = self._check()
        self.assertIn('can both render token', '\n'.join(problems))

    def test_matrix_rows_get_their_own_tokens(self):
        self._workflow('a.yml', """
jobs:
  lane:
    strategy:
      matrix:
        test: [{'name': 'alpha'}, {'name': 'beta'}]
    runs-on: [self-hosted, bound-debian-13, bound-l, "bind-${{ github.run_id
      }}-${{ github.run_attempt }}-${{ matrix.test.name }}-${{
      strategy.job-index }}"]
""")
        self.assertEqual([], self._check())

    def test_two_matrix_jobs_reusing_an_entry_name_collide(self):
        # The collision item 2 of the review raised: uniqueness rests on
        # matrix entry names differing across bound jobs, so assert it
        # rather than trusting it.
        token = ('"bind-${{ github.run_id }}-${{ github.run_attempt }}-'
                 '${{ matrix.test.name }}-${{ strategy.job-index }}"')
        self._workflow('a.yml', """
jobs:
  one:
    strategy:
      matrix:
        test: [{'name': 'shared'}]
    runs-on: [self-hosted, bound-debian-13, bound-l, %s]
  two:
    strategy:
      matrix:
        test: [{'name': 'shared'}]
    runs-on: [self-hosted, bound-debian-13, bound-l, %s]
""" % (token, token))
        self.assertIn('can both render token', '\n'.join(self._check()))

    def test_an_unknown_expression_is_reported_not_ignored(self):
        self._workflow('a.yml',
                       'jobs:\n  lane:\n'
                       '    runs-on: [self-hosted, bound-debian-13, bound-l,'
                       ' "bind-${{ github.run_id }}-'
                       '${{ github.run_attempt }}-${{ github.actor }}"]\n')
        problems = self._check()
        self.assertEqual(1, len(problems), problems)
        self.assertIn('not an expression this script expands', problems[0])

    def test_a_tree_with_no_bound_job_is_clean(self):
        self._workflow('a.yml',
                       'jobs:\n  pool:\n'
                       '    runs-on: [self-hosted, vm, debian-13, l]\n')
        self.assertEqual([], self._check())


class RealTreeCase(testtools.TestCase):
    """The repository's own workflows must satisfy the invariant."""

    def test_the_tree_passes(self):
        problems = check_bound_runners.check(
            _ROOT / '.github' / 'workflows',
            _ROOT / '.github' / 'actionlint.yaml')
        self.assertEqual([], problems)

    def test_the_bound_jobs_are_the_three_we_expect(self):
        jobs = check_bound_runners.read_jobs(_ROOT / '.github' / 'workflows')
        bound = sorted(
            '%s:%s' % (path, job_id) for path, job_id, job in jobs
            if check_bound_runners._is_bound(
                check_bound_runners.labels_of(job)))
        self.assertEqual(
            ['functional-tests.yml:openstack_matrix',
             'functional-tests.yml:ovirt_matrix',
             'sf-e2e-functional.yml:sf-e2e'], bound)
