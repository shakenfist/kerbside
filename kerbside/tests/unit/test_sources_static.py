import unittest
from unittest import mock

from kerbside.sources import static as static_source


# A minimal valid console entry used across multiple tests.
_VALID_CONSOLE = {
    'uuid': 'aaaaaaaa-0000-0000-0000-000000000001',
    'name': 'test-vm',
    'hypervisor': 'localhost',
    'hypervisor_ip': '127.0.0.1',
    'insecure_port': 5910,
    'ticket': 'secret-spice-password',
}


def _make_source(consoles, source_name='test-static'):
    """Instantiate StaticSource with the given consoles list."""
    return static_source.StaticSource(
        source=source_name,
        type='static',
        consoles=consoles,
    )


class TestStaticSourceEmptyList(unittest.TestCase):
    """An empty consoles list should construct cleanly and yield nothing."""

    def test_empty_list_no_error(self):
        src = _make_source([])
        self.assertFalse(src.errored)

    def test_empty_list_yields_nothing(self):
        src = _make_source([])
        results = list(src())
        self.assertEqual([], results)


class TestStaticSourceSingleEntry(unittest.TestCase):
    """A single valid console entry should construct and yield one dict."""

    def setUp(self):
        self.src = _make_source([_VALID_CONSOLE])

    def test_no_error(self):
        self.assertFalse(self.src.errored)

    def test_yields_one_console(self):
        results = list(self.src())
        self.assertEqual(1, len(results))

    def test_yielded_dict_fields(self):
        result = list(self.src())[0]
        self.assertEqual(_VALID_CONSOLE['uuid'], result['uuid'])
        self.assertEqual(_VALID_CONSOLE['name'], result['name'])
        self.assertEqual(_VALID_CONSOLE['hypervisor'], result['hypervisor'])
        self.assertEqual(_VALID_CONSOLE['hypervisor_ip'], result['hypervisor_ip'])
        self.assertEqual(_VALID_CONSOLE['insecure_port'], result['insecure_port'])
        self.assertEqual(_VALID_CONSOLE['ticket'], result['ticket'])
        self.assertEqual('test-static', result['source'])

    def test_optional_fields_default_to_none(self):
        result = list(self.src())[0]
        self.assertIsNone(result['secure_port'])
        self.assertIsNone(result['host_subject'])

    def test_optional_fields_explicit(self):
        console = dict(_VALID_CONSOLE)
        console['secure_port'] = 5920
        console['host_subject'] = 'CN=myhost'
        src = _make_source([console])
        result = list(src())[0]
        self.assertEqual(5920, result['secure_port'])
        self.assertEqual('CN=myhost', result['host_subject'])


class TestStaticSourceMultiEntry(unittest.TestCase):
    """Multiple entries should be yielded in insertion order."""

    def setUp(self):
        self.consoles = [
            dict(_VALID_CONSOLE, uuid='aaaaaaaa-0000-0000-0000-000000000001',
                 name='vm-1'),
            dict(_VALID_CONSOLE, uuid='aaaaaaaa-0000-0000-0000-000000000002',
                 name='vm-2'),
            dict(_VALID_CONSOLE, uuid='aaaaaaaa-0000-0000-0000-000000000003',
                 name='vm-3'),
        ]
        self.src = _make_source(self.consoles)

    def test_no_error(self):
        self.assertFalse(self.src.errored)

    def test_yields_all_consoles(self):
        results = list(self.src())
        self.assertEqual(3, len(results))

    def test_uuids_are_preserved(self):
        results = list(self.src())
        uuids = [r['uuid'] for r in results]
        expected = [c['uuid'] for c in self.consoles]
        self.assertEqual(sorted(expected), sorted(uuids))


class TestStaticSourceMissingRequiredField(unittest.TestCase):
    """Missing required fields should set errored=True and log an error."""

    def _test_missing(self, field):
        console = dict(_VALID_CONSOLE)
        del console[field]
        with mock.patch.object(
                static_source.LOG, 'error') as mock_log_error:
            src = _make_source([console])
        self.assertTrue(src.errored,
                        msg=f'errored should be True when {field!r} is missing')
        mock_log_error.assert_called()

    def test_missing_uuid(self):
        self._test_missing('uuid')

    def test_missing_name(self):
        self._test_missing('name')

    def test_missing_hypervisor(self):
        self._test_missing('hypervisor')

    def test_missing_hypervisor_ip(self):
        self._test_missing('hypervisor_ip')

    def test_missing_insecure_port(self):
        self._test_missing('insecure_port')

    def test_missing_ticket(self):
        self._test_missing('ticket')


class TestStaticSourceDuplicateUuid(unittest.TestCase):
    """Duplicate UUIDs should produce a warning; the last entry wins."""

    def setUp(self):
        self.console_first = dict(_VALID_CONSOLE, ticket='first-ticket')
        self.console_last = dict(_VALID_CONSOLE, ticket='last-ticket')

    def test_no_error_on_duplicate(self):
        with mock.patch.object(static_source.LOG, 'warning'):
            src = _make_source([self.console_first, self.console_last])
        self.assertFalse(src.errored)

    def test_warning_is_logged(self):
        with mock.patch.object(
                static_source.LOG, 'warning') as mock_warn:
            _make_source([self.console_first, self.console_last])
        mock_warn.assert_called()
        warning_text = str(mock_warn.call_args)
        self.assertIn(_VALID_CONSOLE['uuid'], warning_text)

    def test_last_definition_wins(self):
        with mock.patch.object(static_source.LOG, 'warning'):
            src = _make_source([self.console_first, self.console_last])
        results = list(src())
        self.assertEqual(1, len(results))
        self.assertEqual('last-ticket', results[0]['ticket'])


class TestStaticSourceClose(unittest.TestCase):
    """close() should be a no-op and not raise."""

    def test_close_is_noop(self):
        src = _make_source([])
        # Should not raise
        src.close()


if __name__ == '__main__':
    unittest.main()
