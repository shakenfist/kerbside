import importlib.util
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import testtools


# precache-image.py lives in tools/ovirt-e2e/ (outside the importable
# package) and its filename contains a hyphen, so load it by path. It
# imports shakenfist_client inside main(), and that is deliberately not a
# test dependency: the script runs with the CI runner's system-wide client.
# Each test supplies a fake module instead.
_PRECACHE_PATH = (
    Path(__file__).resolve().parents[3] / 'tools' / 'ovirt-e2e' / 'precache-image.py')


def _load_tool():
    spec = importlib.util.spec_from_file_location('ovirt_precache_image', _PRECACHE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


precache_image = _load_tool()


class PrecacheImageTestCase(testtools.TestCase):
    def run_tool(self, client, argv=('rocky:8', 'runner-ns', '--poll', '7', '--timeout', '30'), clock=None):
        # A fake clock advancing a second per reading, so that a wait which
        # never ends -- as a broken state check would make it -- reaches the
        # timeout at once rather than spinning on the real one.
        clock = clock or iter(range(100000))
        apiclient = mock.Mock()
        apiclient.Client.return_value = client
        package = mock.Mock(apiclient=apiclient)
        out = io.StringIO()
        with mock.patch.dict(sys.modules, {'shakenfist_client': package,
                                           'shakenfist_client.apiclient': apiclient}), \
                mock.patch.object(sys, 'argv', ['precache-image.py', *argv]), \
                mock.patch.object(precache_image.time, 'sleep') as self.sleep, \
                mock.patch.object(precache_image.time, 'time', side_effect=lambda: next(clock)), \
                redirect_stdout(out):
            rc = precache_image.main()
        return rc, out.getvalue()

    def test_waits_until_the_artifact_is_created(self):
        client = mock.Mock()
        client.cache_artifact.return_value = {'uuid': 'a1', 'state': 'initial'}
        client.get_artifact.side_effect = [{'state': 'initial'}, {'state': 'initial'},
                                           {'state': 'created'}]
        rc, out = self.run_tool(client)

        self.assertEqual(0, rc)
        # In the namespace the lane's instances are created in, which is
        # what makes the instance's disk resolve to this artifact.
        client.cache_artifact.assert_called_once_with('rocky:8', namespace='runner-ns')
        self.assertEqual(3, client.get_artifact.call_count)
        client.get_artifact.assert_called_with('a1')
        # Waiting the poll interval before each check, not hammering the API.
        self.assertEqual([mock.call(7)] * 3, self.sleep.call_args_list)
        self.assertIn('rocky:8 is cached', out)
        self.assertNotIn('::warning::', out)

    def test_an_already_created_artifact_returns_at_once(self):
        client = mock.Mock()
        client.cache_artifact.return_value = {'uuid': 'a1', 'state': 'created'}
        rc, out = self.run_tool(client)

        self.assertEqual(0, rc)
        client.get_artifact.assert_not_called()

    def test_a_failed_fetch_warns_and_does_not_fail_the_job(self):
        client = mock.Mock()
        client.cache_artifact.return_value = {'uuid': 'a1', 'state': 'initial'}
        client.get_artifact.return_value = {'state': 'error'}
        rc, out = self.run_tool(client)

        self.assertEqual(0, rc)
        self.assertIn('::warning::', out)
        self.assertIn('state error', out)

    def test_a_failed_request_warns_and_does_not_fail_the_job(self):
        client = mock.Mock()
        client.cache_artifact.side_effect = Exception('403 forbidden')
        rc, out = self.run_tool(client)

        self.assertEqual(0, rc)
        self.assertIn('::warning::', out)
        self.assertIn('403 forbidden', out)

    def test_gives_up_waiting_after_the_timeout(self):
        client = mock.Mock()
        client.cache_artifact.return_value = {'uuid': 'a1', 'state': 'initial'}
        client.get_artifact.return_value = {'state': 'initial'}
        rc, out = self.run_tool(client, clock=iter(range(0, 1000, 20)))

        self.assertEqual(0, rc)
        self.assertIn('still initial after 30 seconds', out)
