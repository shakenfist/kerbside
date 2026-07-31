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


def _instance(node='node-uuid-1', namespace='proj', uuid='u1', name='vm1'):
    # Shaken Fist reports the placement node as a UUID, not a hostname.
    return {
        'uuid': uuid,
        'state': 'created',
        'video': {'vdi': 'spice'},
        'node': node,
        'vdi_port': 5900,
        'vdi_tls_port': 5901,
        'name': name,
        'namespace': namespace,
    }


def _node(fqdn='n1', uuid='node-uuid-1', ip='10.0.0.1', cert_subject=None):
    # Mirror Shaken Fist's node external_view: a UUID plus an fqdn exposed as
    # both 'name' and 'fqdn'. Instances reference the node by its UUID.
    node = {'uuid': uuid, 'name': fqdn, 'fqdn': fqdn, 'ip': ip}
    if cert_subject is not None:
        node['spice_server_cert_subject'] = cert_subject
    return node


class ScrapeTestCase(testtools.TestCase):
    """Tests for ShakenFistSource.__call__ scraping behaviour."""

    def setUp(self):
        super().setUp()
        # __call__ bails out early unless the client module imported.
        client_patch = mock.patch(
            'kerbside.sources.shakenfist.SHAKENFIST_CLIENT', mock.Mock())
        client_patch.start()
        self.addCleanup(client_patch.stop)

    def _make_bare_source(self, **args):
        src = shakenfist_source.ShakenFistSource.__new__(
            shakenfist_source.ShakenFistSource)
        args.setdefault('source', 'sf1')
        src.args = args
        return src

    def _system_client(self, node):
        client = mock.Mock()
        client.get_nodes.return_value = [node]
        return client

    def test_scrape_uses_all_true_under_system_credential(self):
        src = self._make_bare_source(username='system')
        system_client = self._system_client(
            _node(cert_subject='CN=n1'))
        system_client.get_instances.return_value = [_instance()]

        with mock.patch.object(
                src, '_make_client', return_value=system_client):
            consoles = list(src())

        system_client.get_instances.assert_called_once_with(all=True)
        self.assertEqual(1, len(consoles))
        # The hypervisor is the node fqdn (a connectable host), resolved from
        # the instance's node UUID -- never the UUID itself.
        self.assertEqual('n1', consoles[0]['hypervisor'])
        self.assertNotEqual('node-uuid-1', consoles[0]['hypervisor'])
        self.assertEqual('10.0.0.1', consoles[0]['hypervisor_ip'])
        self.assertEqual('CN=n1', consoles[0]['host_subject'])

    def test_scrape_namespaced_under_non_system_credential(self):
        src = self._make_bare_source(username='proj')
        system_client = self._system_client(_node())
        ns_client = mock.Mock()
        ns_client.get_instances.return_value = [_instance()]

        clients = {'system': system_client, 'proj': ns_client}
        with mock.patch.object(
                src, '_make_client', side_effect=lambda ns: clients[ns]):
            consoles = list(src())

        # The namespaced client lists only its own namespace (no all=True),
        # and the system client is used solely for the node map.
        ns_client.get_instances.assert_called_once_with()
        system_client.get_instances.assert_not_called()
        self.assertEqual(1, len(consoles))

    def test_host_subject_none_when_node_lacks_field(self):
        src = self._make_bare_source(username='system')
        system_client = self._system_client(_node())
        system_client.get_instances.return_value = [_instance()]

        with mock.patch.object(
                src, '_make_client', return_value=system_client):
            consoles = list(src())

        self.assertIsNone(consoles[0]['host_subject'])

    def test_host_subject_synthesized_when_flag_set(self):
        src = self._make_bare_source(
            username='system', synthesize_host_subject=True)
        system_client = self._system_client(_node())
        system_client.get_instances.return_value = [_instance()]

        with mock.patch.object(
                src, '_make_client', return_value=system_client):
            consoles = list(src())

        self.assertEqual('CN=n1', consoles[0]['host_subject'])

    def test_published_subject_wins_over_synthesis(self):
        src = self._make_bare_source(
            username='system', synthesize_host_subject=True)
        system_client = self._system_client(
            _node(cert_subject='C=US,CN=n1'))
        system_client.get_instances.return_value = [_instance()]

        with mock.patch.object(
                src, '_make_client', return_value=system_client):
            consoles = list(src())

        self.assertEqual('C=US,CN=n1', consoles[0]['host_subject'])

    def test_instance_on_unknown_node_skipped(self):
        src = self._make_bare_source(username='system')
        system_client = self._system_client(_node())
        system_client.get_instances.return_value = [
            _instance(node='node-uuid-ghost')]

        with mock.patch.object(
                src, '_make_client', return_value=system_client):
            consoles = list(src())

        self.assertEqual([], consoles)


class SigningKeyRefreshTestCase(testtools.TestCase):
    """Signing keys refresh via per-tick source re-instantiation.

    The maintenance loop rebuilds each source every tick, and __init__
    fetches the keys, so there is no separate refresh timer (phase 6
    decision 3). This documents that construction re-runs the fetch.
    """

    def test_construction_refetches_signing_keys(self):
        client = mock.Mock()
        client.get_cluster_cacert.return_value = 'CA'

        with mock.patch(
                'kerbside.sources.shakenfist.SHAKENFIST_CLIENT', mock.Mock()), \
             mock.patch(
                'kerbside.sources.shakenfist._build_client',
                return_value=client), \
             mock.patch.object(
                shakenfist_source.ShakenFistSource,
                'fetch_signing_keys') as mock_fetch:
            src = shakenfist_source.ShakenFistSource(
                source='sf1', username='system', password='k',
                url='https://sf', ca_cert='CA')

        self.assertFalse(src.errored)
        mock_fetch.assert_called_once_with()
