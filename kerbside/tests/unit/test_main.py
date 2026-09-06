from contextlib import contextmanager
from unittest import mock
import os
import tempfile
import testtools
import yaml

# UUID shared across the static-source dispatch tests.
_STATIC_CONSOLE_UUID = 'cccccccc-0000-0000-0000-000000000001'


class FakeConfig:
    SOURCES_PATH = None
    NODE_NAME = 'test-node'


fake_config = FakeConfig()


class ParseSourcesTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()

        # Mock the config module
        self.config_patch = mock.patch('kerbside.main.config', fake_config)
        self.mock_config = self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

        # Mock database functions
        db_get_sources_patcher = mock.patch('kerbside.db.get_sources',
                                            return_value=[])
        self.mock_db_get_sources = db_get_sources_patcher.start()
        self.addCleanup(db_get_sources_patcher.stop)

        db_get_consoles_patcher = mock.patch('kerbside.db.get_consoles',
                                             return_value=[])
        self.mock_db_get_consoles = db_get_consoles_patcher.start()
        self.addCleanup(db_get_consoles_patcher.stop)

        db_get_source_patcher = mock.patch('kerbside.db.get_source',
                                           return_value=None)
        self.mock_db_get_source = db_get_source_patcher.start()
        self.addCleanup(db_get_source_patcher.stop)

        db_add_source_patcher = mock.patch('kerbside.db.add_source')
        self.mock_db_add_source = db_add_source_patcher.start()
        self.addCleanup(db_add_source_patcher.stop)

        db_set_error_patcher = mock.patch(
            'kerbside.db.set_source_error_state')
        self.mock_db_set_source_error_state = db_set_error_patcher.start()
        self.addCleanup(db_set_error_patcher.stop)

        db_add_console_patcher = mock.patch('kerbside.db.add_console',
                                            return_value=True)
        self.mock_db_add_console = db_add_console_patcher.start()
        self.addCleanup(db_add_console_patcher.stop)

        db_add_audit_patcher = mock.patch('kerbside.db.add_audit_event')
        self.mock_db_add_audit_event = db_add_audit_patcher.start()
        self.addCleanup(db_add_audit_patcher.stop)

        db_remove_console_patcher = mock.patch('kerbside.db.remove_console')
        self.mock_db_remove_console = db_remove_console_patcher.start()
        self.addCleanup(db_remove_console_patcher.stop)

        db_delete_source_patcher = mock.patch('kerbside.db.delete_source')
        self.mock_db_delete_source = db_delete_source_patcher.start()
        self.addCleanup(db_delete_source_patcher.stop)

        # Mock source implementations
        shakenfist_patcher = mock.patch(
            'kerbside.sources.shakenfist.ShakenFistSource')
        self.mock_shakenfist_source = shakenfist_patcher.start()
        self.addCleanup(shakenfist_patcher.stop)

        ovirt_patcher = mock.patch(
            'kerbside.sources.ovirt.oVirtSource')
        self.mock_ovirt_source = ovirt_patcher.start()
        self.addCleanup(ovirt_patcher.stop)

        static_patcher = mock.patch(
            'kerbside.sources.static.StaticSource')
        self.mock_static_source = static_patcher.start()
        self.addCleanup(static_patcher.stop)

    @contextmanager
    def _create_sources_yaml(self, sources):
        """Context manager to create a temporary sources.yaml file."""
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        try:
            yaml.dump(sources, f)
            f.close()
            fake_config.SOURCES_PATH = f.name
            yield f.name
        finally:
            if os.path.exists(f.name):
                os.unlink(f.name)

    def _mock_source_lookup(self, consoles=None, errored=False):
        """Helper to create a mock source lookup."""
        if consoles is None:
            consoles = []
        mock_lookup = mock.MagicMock()
        mock_lookup.errored = errored
        # When called as lookup(), it should return the consoles list (which is iterable)
        mock_lookup.return_value = consoles
        return mock_lookup

    @mock.patch('os.path.exists', return_value=False)
    def test_parse_sources_no_config_file(self, mock_exists):
        from kerbside import main

        fake_config.SOURCES_PATH = '/nonexistent/sources.yaml'
        main._parse_sources()

        # Should not attempt to add any sources if config file doesn't exist
        self.assertFalse(self.mock_db_add_source.called)

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_new_shakenfist_source(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = self._mock_source_lookup()

            main._parse_sources()
            self.mock_db_add_source.assert_called_once_with(
                'test-sf', 'shakenfist', 'http://localhost:13000',
                'admin', 'secret',
                project_name=None,
                user_domain_id=None,
                project_domain_id=None,
                errored=False,
                ca_cert=None
            )

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_update_existing_source(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13001',
            'username': 'admin',
            'password': 'newsecret'
        }]):
            existing_source = {
                'name': 'test-sf',
                'type': 'shakenfist',
                'url': 'http://localhost:13000',
                'username': 'admin',
                'password': 'oldsecret',
                'project_name': None,
                'user_domain_id': None,
                'project_domain_id': None,
                'deleted': False,
                'ca_cert': None
            }

            self.mock_shakenfist_source.return_value = self._mock_source_lookup()
            self.mock_db_get_source.return_value = existing_source

            main._parse_sources()
            # Should be called to update the source due to changed url and password
            self.mock_db_add_source.assert_called_once()

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_openstack_skipped(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-os',
            'type': 'openstack',
            'url': 'http://localhost:5000',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_id': 'default',
            'project_domain_id': 'default'
        }]):
            self.mock_db_get_source.return_value = None

            main._parse_sources()
            # OpenStack sources should be added to DB but not scraped
            self.mock_db_add_source.assert_called_once()
            # Should not try to create OpenStack source lookup
            self.assertFalse(self.mock_shakenfist_source.called)
            self.assertFalse(self.mock_ovirt_source.called)

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_with_consoles(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            mock_console = {
                'source': 'test-sf',
                'uuid': 'console-uuid-1',
                'hypervisor': 'hypervisor1',
                'hypervisor_ip': '192.168.1.1',
                'insecure_port': 5900,
                'secure_port': 5901,
                'name': 'test-vm',
                'host_subject': 'CN=test',
                'ticket': 'ticket123'
            }
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = self._mock_source_lookup(
                consoles=[mock_console])

            self.mock_db_add_console.return_value = True
            main._parse_sources()
            self.mock_db_add_console.assert_called_once_with(**mock_console)
            # Should log audit event for new console
            self.mock_db_add_audit_event.assert_called()

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_unknown_type(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-unknown',
            'type': 'unknown_type',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None

            main._parse_sources()
            # Should set error state for unknown source type
            self.mock_db_set_source_error_state.assert_called_with('test-unknown', True)

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_lookup_exception(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            # Mock the source lookup to raise an exception
            self.mock_shakenfist_source.side_effect = Exception('Connection failed')

            main._parse_sources()
            # Should set error state when exception occurs
            self.mock_db_set_source_error_state.assert_called_with('test-sf', True)

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_cleanup_extra_consoles(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = self._mock_source_lookup()

            # Mock existing console in database
            existing_console = {
                'source': 'test-sf',
                'uuid': 'old-console-uuid',
                'name': 'old-vm'
            }
            self.mock_db_get_consoles.return_value = [existing_console]

            main._parse_sources()
            # Should remove console that is no longer available
            self.mock_db_remove_console.assert_called_once_with(
                source='test-sf', uuid='old-console-uuid')

    @mock.patch('os.path.exists', return_value=True)
    def test_exception_mid_scrape_retains_the_inventory(self, mock_exists):
        """A source which raises must not have its consoles deleted.

        The cleanup infers "this console is gone" from "I did not see it
        this pass". That inference is only sound for a source we managed
        to enumerate. A source which raised told us nothing at all, and
        deleting on no information destroys the operator's console
        inventory over a transient network error.
        """
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.side_effect = Exception(
                'connection reset by peer')
            self.mock_db_get_consoles.return_value = [{
                'source': 'test-sf',
                'uuid': 'live-console-uuid',
                'name': 'a-vm'
            }]

            main._parse_sources()

            self.assertFalse(self.mock_db_remove_console.called)
            # The source is still marked errored -- retaining consoles is
            # not the same as pretending the scrape worked.
            self.mock_db_set_source_error_state.assert_called_with(
                'test-sf', True)

    @mock.patch('os.path.exists', return_value=True)
    def test_errored_source_retains_the_inventory(self, mock_exists):
        """A source which fails to initialise keeps its consoles."""
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = (
                self._mock_source_lookup(errored=True))
            self.mock_db_get_consoles.return_value = [{
                'source': 'test-sf',
                'uuid': 'live-console-uuid',
                'name': 'a-vm'
            }]

            main._parse_sources()

            self.assertFalse(self.mock_db_remove_console.called)

    @mock.patch('os.path.exists', return_value=True)
    def test_unknown_source_type_retains_the_inventory(self, mock_exists):
        """An unrecognised type is not evidence its consoles are gone."""
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-weird',
            'type': 'not-a-real-source-type',
            'url': 'http://localhost:13000'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_db_get_consoles.return_value = [{
                'source': 'test-weird',
                'uuid': 'live-console-uuid',
                'name': 'a-vm'
            }]

            main._parse_sources()

            self.assertFalse(self.mock_db_remove_console.called)

    @mock.patch('os.path.exists', return_value=True)
    def test_openstack_consoles_are_retained(self, mock_exists):
        """Openstack sources are not scraped, so nothing is inferred.

        This used to be a hardcoded source-type check in the cleanup. It
        is now a consequence of openstack never reaching the scrape loop,
        which is why the behaviour is asserted here rather than assumed.
        """
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-os',
            'type': 'openstack',
            'url': 'http://localhost:5000',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_id': 'default',
            'project_domain_id': 'default'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_db_get_consoles.return_value = [{
                'source': 'test-os',
                'uuid': 'os-console-uuid',
                'name': 'a-vm'
            }]

            main._parse_sources()

            self.assertFalse(self.mock_db_remove_console.called)

    @mock.patch('os.path.exists', return_value=True)
    def test_a_failing_source_does_not_affect_a_healthy_one(self, mock_exists):
        """Retention is per source, not all or nothing.

        A healthy source's stale consoles must still be cleaned up while
        an unhealthy sibling's are retained -- otherwise one broken
        cluster freezes cleanup for every other one.
        """
        from kerbside import main

        sources = [
            {
                'source': 'broken-sf',
                'type': 'shakenfist',
                'url': 'http://localhost:13000',
                'username': 'admin',
                'password': 'secret'
            },
            {
                'source': 'healthy-static',
                'type': 'static',
                'url': 'http://localhost:13000'
            }]
        with self._create_sources_yaml(sources):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = (
                self._mock_source_lookup(errored=True))
            self.mock_static_source.return_value = self._mock_source_lookup()
            self.mock_db_get_consoles.return_value = [
                {'source': 'broken-sf', 'uuid': 'keep-me', 'name': 'a-vm'},
                {'source': 'healthy-static', 'uuid': 'drop-me', 'name': 'b-vm'},
            ]

            main._parse_sources()

            self.mock_db_remove_console.assert_called_once_with(
                source='healthy-static', uuid='drop-me')

    @mock.patch('os.path.exists', return_value=True)
    def test_removed_source_still_has_its_consoles_deleted(self, mock_exists):
        """A source deleted from the configuration is the exception.

        It is never scraped, but it is genuinely gone: the source row is
        deleted immediately below the console cleanup, so retaining its
        consoles would orphan them permanently. Before the cleanup was
        scoped this case raised KeyError out of the source-type lookup
        and took the whole scrape down with it.
        """
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = self._mock_source_lookup()
            self.mock_db_get_sources.return_value = [
                {'name': 'test-sf', 'type': 'shakenfist'},
                {'name': 'departed-sf', 'type': 'shakenfist'},
            ]
            self.mock_db_get_consoles.return_value = [{
                'source': 'departed-sf',
                'uuid': 'orphan-uuid',
                'name': 'a-vm'
            }]

            main._parse_sources()

            self.mock_db_remove_console.assert_called_once_with(
                source='departed-sf', uuid='orphan-uuid')
            self.mock_db_delete_source.assert_called_once_with('departed-sf')

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_cleanup_extra_sources(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_shakenfist_source.return_value = self._mock_source_lookup()

            # Mock existing extra source in database
            existing_sources = [
                {'name': 'test-sf', 'type': 'shakenfist'},
                {'name': 'old-source', 'type': 'shakenfist'}
            ]
            self.mock_db_get_sources.return_value = existing_sources

            main._parse_sources()
            # Should delete source that is no longer in config
            self.mock_db_delete_source.assert_called_once_with('old-source')

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_ovirt_source(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-ovirt',
            'type': 'ovirt',
            'url': 'https://ovirt.example.com',
            'username': 'admin@internal',
            'password': 'secret',
            'ca_cert': '-----BEGIN CERTIFICATE-----\n...'
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_ovirt_source.return_value = self._mock_source_lookup()

            main._parse_sources()
            # Should create oVirt source with CA cert
            self.mock_db_add_source.assert_called_once()
            call_args = self.mock_db_add_source.call_args
            self.assertEqual('test-ovirt', call_args[0][0])
            self.assertEqual('ovirt', call_args[0][1])

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_source_initialization_failed(self, mock_exists):
        from kerbside import main

        with self._create_sources_yaml([{
            'source': 'test-sf',
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret'
        }]):
            self.mock_db_get_source.return_value = None
            # Mock the source lookup with errored=True
            self.mock_shakenfist_source.return_value = self._mock_source_lookup(
                errored=True)

            main._parse_sources()
            # Should set error state when source initialization fails
            self.mock_db_set_source_error_state.assert_called_with('test-sf', True)

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_static_source_dispatch(self, mock_exists):
        """Static source dispatches to StaticSource and passes ticket to db."""
        from kerbside import main

        static_console = {
            'source': 'test-static',
            'uuid': _STATIC_CONSOLE_UUID,
            'name': 'ci-vm',
            'hypervisor': 'localhost',
            'hypervisor_ip': '127.0.0.1',
            'insecure_port': 5910,
            'secure_port': None,
            'host_subject': None,
            'ticket': 'ci-spice-password',
        }
        with self._create_sources_yaml([{
            'source': 'test-static',
            'type': 'static',
            'consoles': [{
                'uuid': _STATIC_CONSOLE_UUID,
                'name': 'ci-vm',
                'hypervisor': 'localhost',
                'hypervisor_ip': '127.0.0.1',
                'insecure_port': 5910,
                'ticket': 'ci-spice-password',
            }]
        }]):
            self.mock_db_get_source.return_value = None
            self.mock_static_source.return_value = self._mock_source_lookup(
                consoles=[static_console])

            self.mock_db_add_console.return_value = True
            main._parse_sources()

            # StaticSource should be constructed
            self.mock_static_source.assert_called_once()

            # db.add_console should be called with the ticket field
            self.mock_db_add_console.assert_called_once_with(**static_console)
            call_kwargs = self.mock_db_add_console.call_args[1]
            self.assertEqual('ci-spice-password', call_kwargs['ticket'])

            # Success path: error state set to False (not True)
            self.mock_db_set_source_error_state.assert_called_with(
                'test-static', False)

            # Audit event should be logged for the new console
            self.mock_db_add_audit_event.assert_called()

    @mock.patch('os.path.exists', return_value=True)
    def test_parse_sources_static_and_other_source_coexist(self, mock_exists):
        """A static source does not break dispatch for other source types."""
        from kerbside import main

        with self._create_sources_yaml([
            {
                'source': 'test-static',
                'type': 'static',
                'consoles': [{
                    'uuid': _STATIC_CONSOLE_UUID,
                    'name': 'ci-vm',
                    'hypervisor': 'localhost',
                    'hypervisor_ip': '127.0.0.1',
                    'insecure_port': 5910,
                    'ticket': 'ci-spice-password',
                }]
            },
            {
                'source': 'test-sf',
                'type': 'shakenfist',
                'url': 'http://localhost:13000',
                'username': 'admin',
                'password': 'secret'
            }
        ]):
            self.mock_db_get_source.return_value = None
            self.mock_static_source.return_value = self._mock_source_lookup()
            self.mock_shakenfist_source.return_value = self._mock_source_lookup()

            main._parse_sources()

            # Both source types should be instantiated
            self.mock_static_source.assert_called_once()
            self.mock_shakenfist_source.assert_called_once()


class _FakeResourceNotFound(Exception):
    """Stand-in for shakenfist_client.apiclient.ResourceNotFoundException."""


class SigningKeyFailureScrapeTestCase(testtools.TestCase):
    """A source whose signing key fetch failed must still be scraped.

    This is the regression guard whose absence let the defect ship. It
    drives the real ShakenFistSource through main._parse_sources() -- only
    the Shaken Fist API client and the db layer are mocked -- because the
    damage was done by main's own control flow, not by the source class:
    an errored source hits the `continue` before the scrape loop, and the
    unconditional cleanup after that loop then deletes every console the
    scrape did not re-report. Asserting on the source class alone cannot
    see that, so this asserts on remove_console.
    """

    def setUp(self):
        super().setUp()

        config_patch = mock.patch('kerbside.main.config', fake_config)
        config_patch.start()
        self.addCleanup(config_patch.stop)

        self.mocks = {}
        for name, kwargs in [
                ('get_sources', {'return_value': []}),
                ('get_consoles', {'return_value': []}),
                ('get_source', {'return_value': None}),
                ('add_source', {}),
                ('set_source_error_state', {}),
                ('add_console', {'return_value': True}),
                ('add_audit_event', {}),
                ('remove_console', {}),
                ('delete_source', {})]:
            patcher = mock.patch('kerbside.db.%s' % name, **kwargs)
            self.mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)

        # The client module is imported by name at runtime, so a fake
        # module carrying the exception class is what the source really
        # sees.
        fake_client_module = mock.Mock()
        fake_client_module.ResourceNotFoundException = _FakeResourceNotFound
        client_patch = mock.patch(
            'kerbside.sources.shakenfist.SHAKENFIST_CLIENT',
            fake_client_module)
        client_patch.start()
        self.addCleanup(client_patch.stop)

    @contextmanager
    def _sources_yaml(self, sources):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        try:
            yaml.dump(sources, f)
            f.close()
            fake_config.SOURCES_PATH = f.name
            yield f.name
        finally:
            if os.path.exists(f.name):
                os.unlink(f.name)

    def _sf_client(self, keys_error):
        client = mock.Mock()
        client.get_cluster_cacert.return_value = 'CA'
        client.get_vdi_token_public_keys.side_effect = keys_error
        client.get_nodes.return_value = [{
            'uuid': 'node-uuid-1', 'name': 'n1', 'fqdn': 'n1',
            'ip': '10.0.0.1'}]
        client.get_instances.return_value = [{
            'uuid': 'console-uuid-1', 'state': 'created',
            'video': {'vdi': 'spice'}, 'node': 'node-uuid-1',
            'vdi_port': 5900, 'vdi_tls_port': 5901,
            'name': 'vm1', 'namespace': 'proj'}]
        return client

    def _run(self, keys_error):
        existing_console = {
            'source': 'test-sf', 'uuid': 'console-uuid-1', 'name': 'vm1'}
        self.mocks['get_consoles'].return_value = [existing_console]

        with self._sources_yaml([{
                'source': 'test-sf',
                'type': 'shakenfist',
                'url': 'http://localhost:13000',
                'username': 'system',
                'password': 'secret',
                'ca_cert': 'CA'}]):
            with mock.patch(
                    'kerbside.sources.shakenfist._build_client',
                    return_value=self._sf_client(keys_error)):
                from kerbside import main
                main._parse_sources()

    def test_absent_signing_keys_do_not_delete_the_inventory(self):
        # A cluster on which sf-ctl ensure-kerbside-signing-key has never
        # been run 404s /admin/vditokenpubkey. That is a normal state.
        self._run(_FakeResourceNotFound('404'))

        # The console the source already had was NOT deleted as "no longer
        # available". This is the assertion that matters: it is the one the
        # defect broke, and it is checked first so a regression reports the
        # deletion rather than the missing scrape that caused it.
        self.mocks['remove_console'].assert_not_called()
        # It was not deleted because the scrape ran and re-saw it.
        self.mocks['add_console'].assert_called_once()
        self.assertEqual(
            'console-uuid-1',
            self.mocks['add_console'].call_args[1]['uuid'])
        # The source is healthy: only token exchange is unavailable.
        self.mocks['set_source_error_state'].assert_called_with(
            'test-sf', False)

    def test_old_client_does_not_delete_the_inventory(self):
        # shakenfist-client older than 0.8.3 has no
        # get_vdi_token_public_keys() at all.
        self._run(AttributeError('get_vdi_token_public_keys'))

        self.mocks['remove_console'].assert_not_called()
        self.mocks['add_console'].assert_called_once()
        self.mocks['set_source_error_state'].assert_called_with(
            'test-sf', False)

    def test_genuine_key_fetch_failure_does_not_delete_the_inventory(self):
        # Connection refused, auth failure, anything else.
        self._run(Exception('connection refused'))

        self.mocks['remove_console'].assert_not_called()
        self.mocks['add_console'].assert_called_once()
        self.mocks['set_source_error_state'].assert_called_with(
            'test-sf', False)

    def test_scrape_failure_still_errors_the_source(self):
        # The separate, correct behaviour is untouched: when the scrape
        # itself fails the source is errored, and the consoles it did not
        # report are still cleaned up.
        existing_console = {
            'source': 'test-sf', 'uuid': 'console-uuid-1', 'name': 'vm1'}
        self.mocks['get_consoles'].return_value = [existing_console]

        client = self._sf_client(None)
        client.get_vdi_token_public_keys.side_effect = None
        client.get_vdi_token_public_keys.return_value = {
            'active_kid': 'k', 'keys': []}
        client.get_nodes.side_effect = Exception('cluster unreachable')

        with self._sources_yaml([{
                'source': 'test-sf',
                'type': 'shakenfist',
                'url': 'http://localhost:13000',
                'username': 'system',
                'password': 'secret',
                'ca_cert': 'CA'}]):
            with mock.patch(
                    'kerbside.sources.shakenfist._build_client',
                    return_value=client), \
                 mock.patch(
                    'kerbside.sources.shakenfist.db.upsert_sf_token_keys'):
                from kerbside import main
                main._parse_sources()

        self.mocks['set_source_error_state'].assert_called_with(
            'test-sf', True)
        self.mocks['add_console'].assert_not_called()
