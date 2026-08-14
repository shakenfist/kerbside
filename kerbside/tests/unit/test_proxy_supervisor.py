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

    def test_env_override_set_but_invalid_raises(self):
        # An explicit override is authoritative: if set but not executable it
        # must fail, not silently fall through to a different binary.
        with mock.patch.dict(
                os.environ,
                {proxy_supervisor.PROXY_BIN_ENV: '/nonexistent/kerbside-proxy'}):
            e = self.assertRaises(RuntimeError, proxy_supervisor.find_proxy_bin)
        self.assertIn(proxy_supervisor.PROXY_BIN_ENV, str(e))

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


OTHER_HASH = 'b' * 64


def _completed(returncode, stdout='', stderr=''):
    """A stand-in for the subprocess.run() result of `--contract-hash`."""
    return subprocess.CompletedProcess(
        args=['/bin/kerbside-proxy', '--contract-hash'], returncode=returncode,
        stdout=stdout, stderr=stderr)


def _env_without_skip():
    """The real environment minus the escape hatch, so a developer who has it
    set in their shell does not silently pass the refusal tests."""
    return {k: v for k, v in os.environ.items()
            if k != proxy_supervisor.SKIP_CONTRACT_CHECK_ENV}


class ContractCheckTestCase(testtools.TestCase):
    def _launch(self, run_result, env=None):
        """Run launch_rust_proxy() with the binary lookup, the contract probe
        and Popen all mocked out. Returns the (run, popen) mocks."""
        if env is None:
            env = _env_without_skip()
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch('kerbside.proxy_supervisor.find_proxy_bin',
                        return_value='/bin/kerbside-proxy'), \
             mock.patch('kerbside.proxy_supervisor.subprocess.run') as run, \
             mock.patch('kerbside.proxy_supervisor.subprocess.Popen') as popen, \
             mock.patch('kerbside.proxy_supervisor.LOG') as log:
            if isinstance(run_result, BaseException):
                run.side_effect = run_result
            else:
                run.return_value = run_result
            try:
                proxy_supervisor.launch_rust_proxy(_fake_config())
            except RuntimeError as e:
                self.raised = e
            else:
                self.raised = None
        return run, popen, log

    def test_matching_hash_launches(self):
        run, popen, _ = self._launch(
            _completed(0, stdout=proxy_supervisor.CONTRACT_HASH + '\n'))
        self.assertIsNone(self.raised)
        run.assert_called_once()
        self.assertEqual(
            ['/bin/kerbside-proxy', '--contract-hash'], run.call_args[0][0])
        popen.assert_called_once()

    def test_mismatched_hash_raises_naming_both_hashes(self):
        _, popen, _ = self._launch(_completed(0, stdout=OTHER_HASH + '\n'))
        self.assertIsNotNone(self.raised)
        self.assertIn(proxy_supervisor.CONTRACT_HASH, str(self.raised))
        self.assertIn(OTHER_HASH, str(self.raised))
        self.assertIn(proxy_supervisor.SKIP_CONTRACT_CHECK_ENV, str(self.raised))
        popen.assert_not_called()

    def test_binary_without_the_flag_raises_predates_message(self):
        # Every kerbside-proxy release <= 0.4.0 rejects the unknown flag.
        _, popen, _ = self._launch(
            _completed(2, stderr='error: unexpected argument \'--contract-hash\' found'))
        self.assertIsNotNone(self.raised)
        self.assertIn('predates the contract handshake', str(self.raised))
        popen.assert_not_called()

    def test_probe_timeout_raises(self):
        _, popen, _ = self._launch(
            subprocess.TimeoutExpired(cmd='kerbside-proxy', timeout=10))
        self.assertIsNotNone(self.raised)
        self.assertIn('predates the contract handshake', str(self.raised))
        popen.assert_not_called()

    def test_malformed_probe_output_raises(self):
        _, popen, _ = self._launch(_completed(0, stdout='not a hash\n'))
        self.assertIsNotNone(self.raised)
        self.assertIn('predates the contract handshake', str(self.raised))
        popen.assert_not_called()

    def test_escape_hatch_launches_despite_mismatch(self):
        env = _env_without_skip()
        env[proxy_supervisor.SKIP_CONTRACT_CHECK_ENV] = '1'
        run, popen, log = self._launch(_completed(0, stdout=OTHER_HASH + '\n'), env=env)
        self.assertIsNone(self.raised)
        popen.assert_called_once()
        # The check is skipped wholesale, so the binary is never even probed.
        run.assert_not_called()
        log.warning.assert_called_once()
        self.assertIn('SKIPPING', log.warning.call_args[0][0])

    def test_explicit_zero_does_not_skip(self):
        env = _env_without_skip()
        env[proxy_supervisor.SKIP_CONTRACT_CHECK_ENV] = '0'
        run, popen, _ = self._launch(_completed(0, stdout=OTHER_HASH + '\n'), env=env)
        self.assertIsNotNone(self.raised)
        run.assert_called_once()
        popen.assert_not_called()


class GetBinaryContractHashTestCase(testtools.TestCase):
    def _probe(self, run_result):
        with mock.patch('kerbside.proxy_supervisor.subprocess.run') as run, \
             mock.patch('kerbside.proxy_supervisor.LOG'):
            if isinstance(run_result, BaseException):
                run.side_effect = run_result
            else:
                run.return_value = run_result
            return proxy_supervisor.get_binary_contract_hash('/bin/kerbside-proxy')

    def test_returns_stripped_hash_on_success(self):
        self.assertEqual(
            OTHER_HASH, self._probe(_completed(0, stdout='  %s \n' % OTHER_HASH)))

    def test_returns_none_on_non_zero_exit(self):
        self.assertIsNone(self._probe(_completed(2, stdout=OTHER_HASH)))

    def test_returns_none_on_timeout(self):
        self.assertIsNone(
            self._probe(subprocess.TimeoutExpired(cmd='kerbside-proxy', timeout=10)))

    def test_returns_none_on_malformed_output(self):
        self.assertIsNone(self._probe(_completed(0, stdout='')))
        self.assertIsNone(self._probe(_completed(0, stdout='not a hash')))
        # Upper case hex is not what the binary emits, so reject it too.
        self.assertIsNone(self._probe(_completed(0, stdout='B' * 64)))


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
