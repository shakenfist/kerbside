import os
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
