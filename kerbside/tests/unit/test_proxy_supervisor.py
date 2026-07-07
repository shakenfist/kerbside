import os
import stat
import subprocess
import tempfile
import types
from unittest import mock

import testtools

from kerbside import proxy_supervisor


def _fake_config(verbose=False):
    """A stand-in for the pydantic config carrying just the launch fields."""
    return types.SimpleNamespace(
        VDI_ADDRESS='0.0.0.0',
        VDI_SECURE_PORT=5900,
        VDI_INSECURE_PORT=5901,
        PROXY_HOST_CERT_PATH='/etc/pki/CA/certs/proxy.pem',
        PROXY_HOST_CERT_KEY_PATH='/etc/pki/CA/certs/proxy-key.pem',
        CACERT_PATH='/etc/pki/CA/ca-cert.pem',
        PROXY_HOST_SUBJECT='C=US,O=Shaken Fist,CN=Kerbside Proxy',
        NODE_NAME='kerbside',
        PROMETHEUS_METRICS_PORT=13003,
        PROMETHEUS_METRICS_ADDRESS='127.0.0.1',
        API_SOCKET_PATH='/run/kerbside/api.sock',
        LOG_VERBOSE=verbose)


class BuildProxyArgvTestCase(testtools.TestCase):
    def test_argv_maps_config_to_flags(self):
        argv = proxy_supervisor.build_proxy_argv('/bin/kerbside-proxy', _fake_config())
        self.assertEqual([
            '/bin/kerbside-proxy',
            '--vdi-address', '0.0.0.0',
            '--secure-port', '5900',
            '--insecure-port', '5901',
            '--cert', '/etc/pki/CA/certs/proxy.pem',
            '--cert-key', '/etc/pki/CA/certs/proxy-key.pem',
            '--cacert', '/etc/pki/CA/ca-cert.pem',
            '--host-subject', 'C=US,O=Shaken Fist,CN=Kerbside Proxy',
            '--node-name', 'kerbside',
            '--prometheus-port', '13003',
            '--metrics-address', '127.0.0.1',
            '--api-socket', '/run/kerbside/api.sock',
        ], argv)

    def test_verbose_flag_present_only_when_log_verbose(self):
        self.assertNotIn('--verbose', proxy_supervisor.build_proxy_argv('b', _fake_config(False)))
        self.assertIn('--verbose', proxy_supervisor.build_proxy_argv('b', _fake_config(True)))


class FindProxyBinTestCase(testtools.TestCase):
    def test_env_override_is_honoured_when_executable(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(tmpdir, ignore_errors=True))
        binary = os.path.join(tmpdir, 'kerbside-proxy')
        with open(binary, 'w') as f:
            f.write('#!/bin/sh\n')
        os.chmod(binary, os.stat(binary).st_mode | stat.S_IEXEC)
        with mock.patch.dict(os.environ, {proxy_supervisor.PROXY_BIN_ENV: binary}):
            self.assertEqual(binary, proxy_supervisor.find_proxy_bin())

    def test_not_found_raises_naming_searched_locations(self):
        # No env override, nothing on PATH, and treat every candidate as
        # non-executable so the in-repo dev binary (if built) is not picked up.
        env = {k: v for k, v in os.environ.items() if k != proxy_supervisor.PROXY_BIN_ENV}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch('kerbside.proxy_supervisor.shutil.which', return_value=None), \
             mock.patch('kerbside.proxy_supervisor.os.access', return_value=False):
            e = self.assertRaises(RuntimeError, proxy_supervisor.find_proxy_bin)
        self.assertIn('kerbside-proxy', str(e))
        self.assertIn(proxy_supervisor.PROXY_BIN_ENV, str(e))


class TerminateChildTestCase(testtools.TestCase):
    def test_clean_exit_after_sigterm_does_not_kill(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.wait.return_value = 0
        proxy_supervisor.terminate_child(proc, 5)
        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()

    def test_sigkill_when_child_overruns_deadline(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd='kerbside-proxy', timeout=5), 0]
        proxy_supervisor.terminate_child(proc, 5)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    def test_already_dead_child_is_a_noop(self):
        proc = mock.Mock()
        proc.poll.return_value = 0
        proxy_supervisor.terminate_child(proc, 5)
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()
