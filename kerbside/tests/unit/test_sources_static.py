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


class TestStaticSourceAbsentConsolesKey(unittest.TestCase):
    """An absent consoles key errors the source (issue #464).

    An errored source keeps what it had published, where one which
    enumerates cleanly with nothing in it has every console deleted.
    Leaving the key out, or misspelling it, must be the former; only
    an explicit empty list (TestStaticSourceEmptyList) is the latter.
    """

    def test_absent_consoles_key_errors(self):
        src = static_source.StaticSource(source='lab', type='static')
        self.assertTrue(src.errored)
        self.assertEqual([], list(src()))

    def test_misspelled_consoles_key_errors(self):
        src = static_source.StaticSource(
            source='lab', type='static', console=[dict(_VALID_CONSOLE)])
        self.assertTrue(src.errored)

    def test_null_consoles_key_errors(self):
        # 'consoles:' with nothing after it parses as None.
        src = _make_source(None)
        self.assertTrue(src.errored)

    @mock.patch.object(static_source, 'LOG')
    def test_error_names_the_keys_without_their_values(self, mock_log):
        static_source.StaticSource(
            source='lab', type='static', console=[dict(_VALID_CONSOLE)])
        message = mock_log.error.call_args[0][0]
        self.assertIn("'console'", message)
        self.assertNotIn(_VALID_CONSOLE['ticket'], message)


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
        self.assertEqual(_VALID_CONSOLE['hypervisor_ip'],
                         result['hypervisor_ip'])
        self.assertEqual(_VALID_CONSOLE['insecure_port'],
                         result['insecure_port'])
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

        # An entry is rejected for missing one field while still
        # carrying the others, so an entry which supplied a ticket and
        # omitted something else must not put that ticket in the log.
        # This is a raw sources.yaml entry: CONSOLE_PUBLIC_FIELDS never
        # sees it, so nothing but this line protects it.
        self.assertNotIn(
            _VALID_CONSOLE['ticket'], str(mock_log_error.call_args),
            msg=f'ticket logged while reporting missing {field!r}')

    def test_error_names_the_problem_without_the_entry(self):
        """Withholding the entry must not cost the operator the diagnostic.

        The message has to say which entry and what is wrong with it,
        or the redaction has traded a credential leak for an
        unactionable error.
        """
        console = dict(_VALID_CONSOLE)
        del console['hypervisor_ip']
        with mock.patch.object(
                static_source.LOG, 'error') as mock_log_error:
            _make_source([console])

        message = str(mock_log_error.call_args)
        self.assertIn('hypervisor_ip', message)
        self.assertIn(_VALID_CONSOLE['uuid'], message)
        self.assertNotIn(_VALID_CONSOLE['ticket'], message)

    def test_error_survives_an_entry_with_no_uuid(self):
        """The uuid is itself a required field, so it may be absent."""
        with mock.patch.object(
                static_source.LOG, 'error') as mock_log_error:
            _make_source([{'ticket': _VALID_CONSOLE['ticket']}])

        message = str(mock_log_error.call_args)
        self.assertIn('<absent>', message)
        self.assertNotIn(_VALID_CONSOLE['ticket'], message)

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


class TestStaticSourceScalarTypes(unittest.TestCase):
    """Hand-written YAML scalars are normalised to their column's type.

    See StaticSourceRoundTripTestCase in test_db.py for why: a value
    kept in YAML's type never compares equal to the stored one.
    """

    def _console(self, **overrides):
        entry = dict(_VALID_CONSOLE)
        entry.update(overrides)
        src = _make_source([entry])
        self.assertFalse(src.errored)
        return list(src())[0]

    def test_unquoted_numbers_become_strings(self):
        console = self._console(uuid=1001, name=4, ticket=123456,
                                host_subject=7)
        self.assertEqual(('1001', '4', '123456', '7'),
                         (console['uuid'], console['name'],
                          console['ticket'], console['host_subject']))

    def test_quoted_ports_become_ints(self):
        console = self._console(insecure_port='5910', secure_port='5911')
        self.assertEqual((5910, 5911),
                         (console['insecure_port'], console['secure_port']))

    def test_absent_optional_fields_stay_none(self):
        console = self._console()
        self.assertIsNone(console['secure_port'])
        self.assertIsNone(console['host_subject'])

    @mock.patch.object(static_source, 'LOG')
    def test_other_types_error_without_logging_the_value(self, mock_log):
        for field, value in (('ticket', ['hunter2']),
                             ('ticket', {'hunter2': 1}),
                             ('ticket', True),
                             ('name', 1.5),
                             ('uuid', ['hunter2']),
                             ('insecure_port', 'hunter2'),
                             ('insecure_port', True),
                             ('insecure_port', None),
                             ('secure_port', 59.1)):
            entry = dict(_VALID_CONSOLE)
            entry[field] = value
            src = _make_source([entry])
            self.assertTrue(src.errored, (field, value))
            self.assertEqual([], list(src()))

        self.assertNotIn('hunter2', repr(mock_log.mock_calls))
