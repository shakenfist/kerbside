from contextlib import contextmanager
from unittest import mock
import os
import tempfile
import testtools
import yaml


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
