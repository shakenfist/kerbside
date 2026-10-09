import os
import tempfile
from unittest import mock

import pydantic
import testtools

from kerbside import config as kerbside_config


class ProxySocketTuningConfigTestCase(testtools.TestCase):
    """The optional proxy socket-tuning fields.

    Unset must stay distinguishable from 0: unset keeps the flag off the
    proxy's command line (so an older binary still starts), while 0 is
    passed through to turn the option off.
    """

    def setUp(self):
        super().setUp()
        # Never read a real /etc/kerbside/kerbside.ini from the test host.
        patcher = mock.patch.object(
            kerbside_config, 'INI_PATH', '/nonexistent/kerbside.ini')
        patcher.start()
        self.addCleanup(patcher.stop)

    def _config(self, **env):
        env = {'KERBSIDE_%s' % k: v for k, v in env.items()}
        with mock.patch.dict(os.environ, env):
            return kerbside_config.Config()

    def test_unset_by_default(self):
        cfg = self._config()
        self.assertIsNone(cfg.PROXY_CLIENT_NOTSENT_LOWAT_BYTES)
        self.assertIsNone(cfg.PROXY_BACKEND_RCVBUF_BYTES)

    def test_empty_value_means_unset(self):
        cfg = self._config(PROXY_CLIENT_NOTSENT_LOWAT_BYTES='',
                           PROXY_BACKEND_RCVBUF_BYTES=' ')
        self.assertIsNone(cfg.PROXY_CLIENT_NOTSENT_LOWAT_BYTES)
        self.assertIsNone(cfg.PROXY_BACKEND_RCVBUF_BYTES)

    def test_zero_is_kept_distinct_from_unset(self):
        cfg = self._config(PROXY_CLIENT_NOTSENT_LOWAT_BYTES='0',
                           PROXY_BACKEND_RCVBUF_BYTES='0')
        self.assertEqual(0, cfg.PROXY_CLIENT_NOTSENT_LOWAT_BYTES)
        self.assertEqual(0, cfg.PROXY_BACKEND_RCVBUF_BYTES)

    def test_values_parse_as_integers(self):
        cfg = self._config(PROXY_CLIENT_NOTSENT_LOWAT_BYTES='65536',
                           PROXY_BACKEND_RCVBUF_BYTES='131072')
        self.assertEqual(65536, cfg.PROXY_CLIENT_NOTSENT_LOWAT_BYTES)
        self.assertEqual(131072, cfg.PROXY_BACKEND_RCVBUF_BYTES)

    def test_negative_values_are_rejected(self):
        self.assertRaises(
            pydantic.ValidationError, self._config,
            PROXY_BACKEND_RCVBUF_BYTES='-1')

    def test_values_beyond_the_proxy_flag_width_are_rejected(self):
        # The proxy's flags are u32; its own test pins the same bound.
        for name in ('PROXY_CLIENT_NOTSENT_LOWAT_BYTES',
                     'PROXY_BACKEND_RCVBUF_BYTES'):
            self.assertEqual(
                2**32 - 1, getattr(self._config(**{name: '4294967295'}), name))
            self.assertRaises(
                pydantic.ValidationError, self._config,
                **{name: '4294967296'})


class KeystoneAuthVerifyConfigTestCase(testtools.TestCase):
    """KEYSTONE_AUTH_VERIFY arrives from the INI file as a string.

    A bool | str field would keep "false" as a string, which requests then
    treats as a CA bundle path (issue #474).
    """

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(
            kerbside_config, 'INI_PATH', '/nonexistent/kerbside.ini')
        patcher.start()
        self.addCleanup(patcher.stop)

    def _verify(self, value):
        with mock.patch.dict(
                os.environ, {'KERBSIDE_KEYSTONE_AUTH_VERIFY': value}):
            return kerbside_config.Config().KEYSTONE_AUTH_VERIFY

    def test_defaults_to_true(self):
        self.assertIs(True, kerbside_config.Config().KEYSTONE_AUTH_VERIFY)

    def test_boolean_strings_become_bools(self):
        for value, expected in [('true', True), ('True', True),
                                ('TRUE', True), (' true ', True),
                                ('false', False), ('False', False),
                                ('FALSE', False)]:
            self.assertIs(expected, self._verify(value), value)

    def test_other_strings_are_ca_bundle_paths(self):
        self.assertEqual('/etc/kerbside/ca.pem',
                         self._verify('/etc/kerbside/ca.pem'))

    def test_empty_value_is_rejected(self):
        # requests treats a falsy verify as "do not verify", so an empty
        # value must not slip through as a path.
        for value in ('', '  '):
            self.assertRaises(
                pydantic.ValidationError, self._verify, value)


class LoadIniSettingsTestCase(testtools.TestCase):
    """An unparseable INI file must stop the process with a failure status.

    A bare sys.exit() exits zero, which a supervisor reads as a clean
    shutdown rather than a failed start (issue #313).
    """

    def _load(self, content):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        path = os.path.join(tmpdir.name, 'kerbside.ini')
        with open(path, 'w') as f:
            f.write(content)
        with mock.patch.object(kerbside_config, 'INI_PATH', path), \
                mock.patch.dict(os.environ, {}, clear=True):
            kerbside_config.load_ini_settings()
            return dict(os.environ)

    def test_unparseable_file_exits_nonzero(self):
        e = self.assertRaises(
            SystemExit, self._load, '[kerbside]\nnot a key value pair\n')
        self.assertEqual(1, e.code)

    def test_lone_percent_exits_nonzero(self):
        # A percent-encoded password is the likely way to get here:
        # interpolation rejects the lone "%".
        e = self.assertRaises(
            SystemExit, self._load,
            '[kerbside]\nsql_url = mysql://kerbside:p%40ss@db/kerbside\n')
        self.assertEqual(1, e.code)

    def test_doubled_percent_is_read_literally(self):
        env = self._load(
            '[kerbside]\nsql_url = mysql://kerbside:p%%40ss@db/kerbside\n')
        self.assertEqual('mysql://kerbside:p%40ss@db/kerbside',
                         env['KERBSIDE_SQL_URL'])
