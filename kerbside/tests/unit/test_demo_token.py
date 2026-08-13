from unittest import mock
import os
import tempfile
import testtools
import yaml

from click.testing import CliRunner

from kerbside import main


_REAL_SEED = 'e6b1c0dd9a2f4b3c8e7d5a1f0b9c2d3e'


class FakeConfig:
    """Stand-in for the pydantic config singleton.

    Only the fields kerbside demo token reads. Defaults are the happy
    path; each test perturbs the one field it is about.
    """

    AUTH_SECRET_SEED = _REAL_SEED
    SOURCES_PATH = None
    API_TOKEN_DURATION = 60
    PUBLIC_FQDN = 'kerbside.example.com'


class DemoTokenTestCase(testtools.TestCase):
    """Guard tests for `kerbside demo token`.

    The minting itself is a single flask-jwt-extended call, so the value
    of this command -- and of these tests -- is entirely in the refusals.
    The command exists because kerbside has no non-Keystone login (issue
    #300), and it must not become a way to hand out credentials for a
    deployment that fronts a real cloud.

    Every guard is fail-closed: an unreadable or empty source list is
    "unknown", not "no non-static sources".
    """

    def setUp(self):
        super().setUp()

        self.fake_config = FakeConfig()
        config_patch = mock.patch('kerbside.main.config', self.fake_config)
        config_patch.start()
        self.addCleanup(config_patch.stop)

        self.runner = CliRunner()

    def _write_sources(self, sources):
        """Write a sources.yaml and point the fake config at it."""
        handle = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False)
        if isinstance(sources, str):
            handle.write(sources)
        else:
            yaml.safe_dump(sources, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        self.fake_config.SOURCES_PATH = handle.name
        return handle.name

    def _invoke(self, subject='demo-admin'):
        return self.runner.invoke(
            main.demo, ['token', '--subject', subject])

    def _assert_refused(self, result, expected_fragment):
        self.assertNotEqual(
            0, result.exit_code,
            'expected a refusal, got exit 0 with output: %s' % result.output)
        self.assertIn(expected_fragment, result.output)

    def test_refuses_an_unconfigured_seed(self):
        self.fake_config.AUTH_SECRET_SEED = '~~unconfigured~~'
        self._write_sources([{'source': 'demo', 'type': 'static'}])

        self._assert_refused(self._invoke(), 'AUTH_SECRET_SEED is unconfigured')

    def test_refuses_a_missing_sources_file(self):
        self.fake_config.SOURCES_PATH = '/nonexistent/sources.yaml'

        self._assert_refused(self._invoke(), 'no sources file at')

    def test_refuses_unparseable_yaml(self):
        self._write_sources('not: [valid\n')

        self._assert_refused(self._invoke(), 'could not read sources from')

    def test_refuses_an_empty_source_list(self):
        self._write_sources([])

        self._assert_refused(self._invoke(), 'defines no sources')

    def test_refuses_a_single_non_static_source(self):
        self._write_sources([{'source': 'prod-ovirt', 'type': 'ovirt'}])

        result = self._invoke()
        self._assert_refused(result, 'is of type "ovirt", not "static"')
        self.assertIn('prod-ovirt', result.output)

    def test_refuses_a_mixed_source_list(self):
        """One real cloud alongside a static source is still a refusal.

        A session JWT is not scoped to a source, so a token minted for
        the static half would authorise consoles on the oVirt half too.
        """
        self._write_sources([
            {'source': 'demo', 'type': 'static'},
            {'source': 'prod-ovirt', 'type': 'ovirt'},
        ])

        self._assert_refused(self._invoke(), 'is of type "ovirt", not "static"')

    def test_mints_for_an_all_static_deployment(self):
        self._write_sources([
            {'source': 'demo', 'type': 'static'},
            {'source': 'demo-two', 'type': 'static'},
        ])

        result = self._invoke()

        self.assertEqual(0, result.exit_code, result.output)

        # stdout carries the token and nothing else, so the command stays
        # pipeable. The warning goes to stderr, which CliRunner folds into
        # output by default -- hence checking the last line specifically.
        token = result.output.strip().split('\n')[-1]
        self.assertEqual(3, len(token.split('.')), 'not a JWT: %s' % token)

    def test_output_writes_a_clean_token_at_0600(self):
        """--output exists because stdout is not a clean channel.

        util.configure_logging() and api.py print startup diagnostics to
        stdout at import time, so a caller doing $(kerbside demo token)
        captures those as well as the token. Scripts use --output; this
        asserts the file holds the token alone, with no trailing newline
        to trip up a shell read, and is not world-readable -- it is a
        bearer credential.
        """
        self._write_sources([{'source': 'demo', 'type': 'static'}])
        target = os.path.join(tempfile.mkdtemp(), 'token.txt')
        self.addCleanup(os.unlink, target)

        result = self.runner.invoke(
            main.demo,
            ['token', '--subject', 'demo-admin', '--output', target])

        self.assertEqual(0, result.exit_code, result.output)

        with open(target) as f:
            written = f.read()

        self.assertEqual(3, len(written.split('.')))
        self.assertEqual(written, written.strip())
        self.assertEqual(0o600, os.stat(target).st_mode & 0o777)

        # The token must not also land on stdout in this mode.
        self.assertNotIn(written, result.output)

    def test_minted_token_is_accepted_by_the_api(self):
        """The token must satisfy the same check the API applies.

        This is the assertion that would catch a claim-shape drift, which
        is the failure the hand-rolled PyJWT snippet this command replaces
        was prone to.
        """
        self._write_sources([{'source': 'demo', 'type': 'static'}])

        result = self._invoke(subject='someone')
        self.assertEqual(0, result.exit_code, result.output)
        token = result.output.strip().split('\n')[-1]

        from flask_jwt_extended import (
            get_jwt, get_jwt_identity, verify_jwt_in_request)
        from kerbside import api

        # The command sets JWT_SECRET_KEY from the validated seed as it
        # mints, so verification here uses that same seed rather than
        # whatever api.py captured at import time.
        self.assertEqual(_REAL_SEED, api.app.config['JWT_SECRET_KEY'])

        with api.app.test_request_context(
                headers={'Authorization': 'Bearer %s' % token}):
            verify_jwt_in_request()
            self.assertEqual('someone', get_jwt_identity())
            # Never read anywhere in the tree, so deliberately absent.
            self.assertNotIn('openstack_token', get_jwt())
