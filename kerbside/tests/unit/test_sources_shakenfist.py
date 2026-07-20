# Unit test for ShakenFistSource.fetch_signing_keys() (matrix cell 12):
# the SF client's get_vdi_token_public_keys() return value must be upserted
# into the sf_token_keys DB row for this source, verbatim as JSON.
#
# fetch_signing_keys() is exercised directly against a bare instance (built
# via __new__ rather than __init__, matching test_sources_static.py's
# preference for constructing the object under test directly) so this stays
# a unit test of that one method rather than a full source-construction
# integration test (which would also need to mock get_cluster_cacert() and
# CA cert comparison, covered elsewhere).

import json
from unittest import mock

import testtools

from kerbside.sources import shakenfist as shakenfist_source


class FetchSigningKeysTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        upsert_patch = mock.patch(
            'kerbside.sources.shakenfist.db.upsert_sf_token_keys')
        self.mock_upsert = upsert_patch.start()
        self.addCleanup(upsert_patch.stop)

    def _make_bare_source(self, source_name='sf1'):
        # Bypass __init__ (cacert fetch/compare, client import) -- this test
        # is only about fetch_signing_keys() in isolation.
        src = shakenfist_source.ShakenFistSource.__new__(
            shakenfist_source.ShakenFistSource)
        src.args = {'source': source_name}
        return src

    def test_fetch_signing_keys_upserts_client_response(self):
        src = self._make_bare_source('sf1')
        keys_payload = {
            'active_kid': 'kid-1',
            'keys': [{
                'kid': 'kid-1', 'alg': 'EdDSA', 'public_pem': 'pub-pem',
                'created': 0,
            }],
        }
        mock_client = mock.Mock()
        mock_client.get_vdi_token_public_keys.return_value = keys_payload

        with mock.patch.object(
                src, '_make_client',
                return_value=mock_client) as mock_make_client:
            src.fetch_signing_keys()

        mock_make_client.assert_called_once_with('system')
        mock_client.get_vdi_token_public_keys.assert_called_once_with()

        self.mock_upsert.assert_called_once()
        call_args = self.mock_upsert.call_args[0]
        self.assertEqual('sf1', call_args[0])
        self.assertEqual(keys_payload, json.loads(call_args[1]))

    def test_fetch_signing_keys_scopes_to_this_source(self):
        src = self._make_bare_source('sf-other')
        mock_client = mock.Mock()
        mock_client.get_vdi_token_public_keys.return_value = {
            'active_kid': 'k', 'keys': []}

        with mock.patch.object(src, '_make_client', return_value=mock_client):
            src.fetch_signing_keys()

        call_args = self.mock_upsert.call_args[0]
        self.assertEqual('sf-other', call_args[0])
