import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import testtools


# check-backend-tls-claims.py lives in tools/ (outside the importable
# package) and its filename contains hyphens, so load it as a module by
# path, exactly as test_check_pypi_storage.py does.
_TOOLS = Path(__file__).resolve().parents[3] / 'tools'
_CHECK_PATH = _TOOLS / 'check-backend-tls-claims.py'
_spec = importlib.util.spec_from_file_location(
    'check_backend_tls_claims', _CHECK_PATH)
check_backend_tls_claims = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_backend_tls_claims)


# The bullet docs/use-cases/ovirt.md carried before phase 4 swept it. A
# VM the engine reports with no host yields no subject, so the claim is
# false as written, and it names no condition at all.
UNCONDITIONAL = """- **The backend leg is pinned.** Kerbside verifies the
  hypervisor's certificate against the engine CA *and* pins the
  certificate subject it discovered from the engine, so a
  redirected backend connection fails rather than succeeding
  quietly.
"""

# The same claim with its condition named, which is what shipped.
CONDITIONAL = """- **The backend leg is pinned where the engine supplies a
  subject.** Kerbside verifies the hypervisor's certificate
  against the engine CA *and* pins the certificate subject it
  discovered from the engine. A VM the engine reports with no
  host leaves that subject unset, and an unset subject relays
  the leg unpinned rather than erroring.
"""

# Review of pull request #469 wrote this into placement.md and the
# check passed, because `configured` was in the conditional vocabulary
# while naming no condition. This is the regression case for that.
CONFIGURED = """- **The WAN leg is encrypted end to end.** Kerbside connects
  to the configured hypervisor over TLS and pins the certificate
  subject it was given, so the long hop is always protected.
"""


def _claims(markdown):
    """Run the check over a temporary file and return its findings."""
    handle, path = tempfile.mkstemp(suffix='.md')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as f:
            f.write(markdown)
        return list(check_backend_tls_claims.claims(path))
    finally:
        os.unlink(path)


class ClaimDetectionTestCase(testtools.TestCase):
    """The cases the check exists for, and the ones it must not flag."""

    def test_unconditional_claim_is_caught(self):
        found = _claims(UNCONDITIONAL)

        self.assertEqual(1, len(found))
        self.assertIn('pinned', found[0][1])

    def test_naming_the_condition_passes(self):
        self.assertEqual([], _claims(CONDITIONAL))

    def test_configured_alone_does_not_exempt_a_block(self):
        """`configured` is a noun modifier, not a condition marker.

        These pages say "configured cloud" and "configured source"
        constantly, so having it in the conditional vocabulary
        exempted most of the corpus. Do not add it back.
        """
        found = _claims(CONFIGURED)

        self.assertEqual(1, len(found))
        self.assertIn('configured hypervisor', found[0][1])

    def test_a_noun_phrase_with_no_finite_verb_is_caught(self):
        """The shape docs/index.md's Use Cases table uses.

        The oVirt row said "host-subject pinned TLS to the hypervisor"
        while the page two lines away had just qualified it. There is
        no finite verb in that cell at all.
        """
        found = _claims(
            '| [oVirt](use-cases/ovirt.md) | Replaces the SPICE proxy '
            'with a front door: host-subject pinned TLS to the '
            'hypervisor | merge tier |\n')

        self.assertEqual(1, len(found))

    def test_should_alone_does_not_exempt_a_block(self):
        """`should` is advice to the reader, not a condition."""
        found = _claims(
            '- **The backend leg is pinned.** Operators should read\n'
            '  the proxy architecture reference for the detail.\n')

        self.assertEqual(1, len(found))

    def test_none_alone_does_not_exempt_a_block(self):
        """`none` is usually a quantifier over something else."""
        found = _claims(
            '- **The backend leg is pinned.** None of the four\n'
            '  sources need extra configuration for it.\n')

        self.assertEqual(1, len(found))

    def test_reachability_is_not_a_claim(self):
        """Naming both ports is a firewall prerequisite, not a claim."""
        self.assertEqual([], _claims(
            'Kerbside needs L3 reachability to every hypervisor\n'
            "node's VDI ports, both the plaintext and TLS ports.\n"))

    def test_a_bare_cross_reference_is_a_known_false_positive(self):
        """Pin this limit so nobody assumes it is handled.

        "is" satisfies the assertion pattern, so a sentence that only
        points at another document reads as a claim. In the tree these
        survive because their block names a condition; standing alone
        they would be flagged, and tightening the pattern to exclude
        them was not worth the claims it would then miss.
        """
        self.assertEqual(1, len(_claims(
            'The full detail of backend pinning is in the proxy\n'
            'architecture reference.\n')))

    def test_fenced_blocks_are_skipped(self):
        """Diagram labels state an outcome the prose conditions."""
        self.assertEqual([], _claims(
            '```mermaid\n'
            'flowchart TD\n'
            '    a -- "the backend leg is pinned" --> b\n'
            '```\n'))


class SentenceSplittingTestCase(testtools.TestCase):
    """Splitting decides what a claim is allowed to be matched against."""

    def test_a_file_name_does_not_end_a_sentence(self):
        """`backend.rs` used to split a claim into two fragments.

        Neither fragment matched on its own, so the split was a false
        negative rather than only a cosmetic problem.
        """
        found = _claims(
            'Per backend.rs the backend leg is pinned to the\n'
            'subject.\n')

        self.assertEqual(1, len(found))
        self.assertIn('backend.rs', found[0][1])
        self.assertTrue(found[0][1].endswith('subject.'))

    def test_emphasis_does_not_truncate_the_reported_sentence(self):
        """The report used to print the mangled `- **The backend leg`."""
        found = _claims(UNCONDITIONAL)

        self.assertEqual(1, len(found))
        self.assertEqual('- The backend leg is pinned.', found[0][1])

    def test_one_finding_per_block(self):
        """A bold lead-in and the sentence expanding it are one claim."""
        self.assertEqual(1, len(_claims(UNCONDITIONAL)))

    def test_snake_case_identifiers_survive(self):
        """Stripping underscore emphasis mangled host_subject."""
        found = _claims(
            'The backend leg is pinned to host_subject always.\n')

        self.assertEqual(1, len(found))
        self.assertIn('host_subject', found[0][1])


class RepositoryTestCase(testtools.TestCase):
    """The check against the tree it ships with."""

    def test_the_use_cases_pages_and_the_index_are_covered(self):
        """docs/index.md is in scope, not only docs/use-cases/.

        Its Use Cases table describes the same pages in the same terms
        and drifted the same way, so dropping it would leave the claim
        restated one directory up from where it was corrected.
        """
        paths = check_backend_tls_claims.default_paths()

        self.assertIn('docs/index.md', paths)
        self.assertIn('docs/use-cases/ovirt.md', paths)

    def test_the_documentation_passes(self):
        self.assertEqual(
            0, check_backend_tls_claims.main(), 'documentation has an '
            'unconditional backend TLS or pinning claim')

    def test_it_reports_rather_than_crashing_without_utf8(self):
        """The pages are full of em dashes.

        Under an ASCII locale an unqualified open() died with a
        UnicodeDecodeError traceback instead of a verdict.
        """
        env = dict(os.environ)
        env.update({'LC_ALL': 'C', 'LANG': 'C', 'PYTHONUTF8': '0',
                    'PYTHONCOERCECLOCALE': '0'})

        result = subprocess.run(
            [sys.executable, str(_CHECK_PATH)], env=env,
            capture_output=True, text=True)

        self.assertNotIn('UnicodeDecodeError', result.stderr)
        self.assertEqual(0, result.returncode, result.stderr)
