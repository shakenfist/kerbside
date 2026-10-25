import socket
import threading
import unittest
from unittest import mock

import requests

from kerbside.sources import base
from kerbside.sources import ovirt as ovirt_source


class _Status(object):
    """The SDK's VmStatus enum, which the source stringifies."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class _Console(object):
    def __init__(self, protocol, address='10.0.0.1', port=5900,
                 tls_port=5901):
        self.id = 'console-%s' % protocol
        self.protocol = protocol
        self.address = address
        self.port = port
        self.tls_port = tls_port


class _Host(object):
    def __init__(self, id, subject):
        self.id = id
        self.certificate = mock.Mock(subject=subject)


class _Vm(object):
    def __init__(self, id, name, status='up', host_id='host-1',
                 consoles=None):
        self.id = id
        self.name = name
        self.status = _Status(status)
        self.host = mock.Mock(id=host_id)
        self.consoles = consoles if consoles is not None else []


class _FakeConnection(object):
    """Enough of the oVirt SDK connection to drive oVirtSource.__call__."""

    def __init__(self, vms, hosts):
        self.vms = vms
        self.hosts = hosts
        self.closed = False

    # -- SDK surface ------------------------------------------------
    def system_service(self):
        return self

    def vms_service(self):
        return self

    def hosts_service(self):
        return self

    def list(self, search=None, current=None):
        if search is None:
            return self.vms
        wanted = search.split('=', 1)[1]
        return [h for h in self.hosts if h.id == wanted]

    def vm_service(self, id):
        vm = next(v for v in self.vms if v.id == id)
        return mock.Mock(
            graphics_consoles_service=lambda: mock.Mock(
                list=lambda current: vm.consoles))

    def close(self):
        self.closed = True


def _make_source(connection, ca_status=200):
    """Build an oVirtSource with the SDK and the CA check stubbed out."""
    sdk = mock.Mock()
    sdk.Connection.return_value = connection
    types = mock.Mock()
    types.GraphicsType.SPICE = 'spice'

    with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
            mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types), \
            mock.patch.object(ovirt_source.requests, 'get') as mock_get:
        mock_get.return_value = mock.Mock(status_code=ca_status, text='CACERT')
        src = ovirt_source.oVirtSource(
            source='test-ovirt', type='ovirt',
            url='https://ovirt.example.com/ovirt-engine',
            username='admin@ovirt@internalsso', password='secret',
            ca_cert='CACERT', ca_file='/dev/null')
    src.ca_get = mock_get
    return src, sdk, types


class TestOVirtSourceDiscovery(unittest.TestCase):
    """Discovery must skip VMs it cannot broker, not abort the scrape."""

    def _scrape(self, vms, hosts):
        connection = _FakeConnection(vms, hosts)
        src, sdk, types = _make_source(connection)
        self.assertFalse(src.errored)
        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types):
            return list(src())

    def test_spice_console_is_yielded(self):
        vms = [_Vm('vm-1', 'desktop-1',
                   consoles=[_Console('spice')])]
        hosts = [_Host('host-1', 'O=local,CN=ovirt.local')]

        results = self._scrape(vms, hosts)

        self.assertEqual(1, len(results))
        self.assertEqual(
            {
                'uuid': 'vm-1',
                'source': 'test-ovirt',
                'hypervisor': '',
                'hypervisor_ip': '10.0.0.1',
                'insecure_port': 5900,
                'secure_port': 5901,
                'name': 'desktop-1',
                'host_subject': 'O=local,CN=ovirt.local',
            },
            results[0])

    def test_vm_which_is_not_up_is_skipped(self):
        vms = [_Vm('vm-1', 'stopped-1', status='down',
                   consoles=[_Console('spice')])]
        hosts = [_Host('host-1', 'O=local,CN=ovirt.local')]

        self.assertEqual([], self._scrape(vms, hosts))

    def test_vm_with_no_spice_console_is_skipped(self):
        """A VNC-only VM has no SPICE console to broker."""
        vms = [_Vm('vm-1', 'vnc-only', consoles=[_Console('vnc')])]
        hosts = [_Host('host-1', 'O=local,CN=ovirt.local')]

        self.assertEqual([], self._scrape(vms, hosts))

    def test_vm_with_no_consoles_at_all_is_skipped(self):
        vms = [_Vm('vm-1', 'headless', consoles=[])]
        hosts = [_Host('host-1', 'O=local,CN=ovirt.local')]

        self.assertEqual([], self._scrape(vms, hosts))

    def test_unbrokerable_vm_does_not_abort_the_scrape(self):
        """The regression: one VNC-only VM used to kill the whole source.

        Discovery is a generator consumed inside a try/except in
        main._parse_sources(). Dereferencing a None console raised
        AttributeError, which was caught as "exception while querying
        source": the source was marked errored, every VM after the
        offending one was never yielded, and those already-known
        consoles were then reaped from the database as no longer
        available -- every scrape, once a minute.
        """
        vms = [
            _Vm('vm-1', 'desktop-1', consoles=[_Console('spice')]),
            _Vm('vm-2', 'vnc-only', consoles=[_Console('vnc')]),
            _Vm('vm-3', 'desktop-2', consoles=[_Console('spice')]),
        ]
        hosts = [_Host('host-1', 'O=local,CN=ovirt.local')]

        results = self._scrape(vms, hosts)

        self.assertEqual(['vm-1', 'vm-3'], [r['uuid'] for r in results])

    def test_host_subject_is_cached_across_vms(self):
        vms = [
            _Vm('vm-1', 'desktop-1', consoles=[_Console('spice')]),
            _Vm('vm-2', 'desktop-2', consoles=[_Console('spice')]),
        ]
        hosts = [_Host('host-1', 'O=local,CN=ovirt.local')]

        results = self._scrape(vms, hosts)

        self.assertEqual(
            ['O=local,CN=ovirt.local', 'O=local,CN=ovirt.local'],
            [r['host_subject'] for r in results])

    def test_scrape_closes_the_connection_it_opened(self):
        vms = [_Vm('vm-1', 'desktop-1', consoles=[_Console('spice')])]
        connection = _FakeConnection(vms, [_Host('host-1', 'CN=h')])
        src, sdk, types = _make_source(connection)
        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types):
            discovered = src()
            next(discovered)
            # The per-VM console lookup reuses the scrape's connection,
            # and must not close it out from under the loop.
            self.assertFalse(connection.closed)
            discovered.close()

        self.assertTrue(connection.closed)
        self.assertEqual(1, sdk.Connection.call_count)


def _console_connection(consoles, granted=None, ticket_error=None):
    """A mock SDK connection whose VM has the given consoles.

    Returns the connection and the console service whose ticket() action
    answers with granted, or raises ticket_error.
    """
    connection = mock.Mock()
    consoles_service = (connection.system_service.return_value
                        .vms_service.return_value
                        .vm_service.return_value
                        .graphics_consoles_service.return_value)
    consoles_service.list.return_value = consoles
    console_service = consoles_service.console_service.return_value
    if ticket_error:
        console_service.ticket.side_effect = ticket_error
    else:
        console_service.ticket.return_value = granted
    return connection, console_service


class _Granted(object):
    """The Ticket the SDK's ticket() action returns: the engine's response."""

    def __init__(self, value, expiry):
        self.value = value
        self.expiry = expiry


class TestOVirtTicketMinting(unittest.TestCase):
    """oVirt mints a ticket with an expiry kerbside chose."""

    NOW = 1700000000.75

    def _mint(self, src, sdk, types, lifetime=90):
        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types), \
                mock.patch.object(ovirt_source.time, 'time',
                                  return_value=self.NOW):
            return src.mint_console_ticket('vm-1', lifetime)

    def _source(self, consoles=None, granted=None, ticket_error=None,
                ca_status=200):
        if consoles is None:
            consoles = [_Console('spice')]
        connection, console_service = _console_connection(
            consoles, granted=granted, ticket_error=ticket_error)
        src, sdk, types = _make_source(connection, ca_status=ca_status)
        return src, sdk, types, connection, console_service

    def test_expiry_is_requested_explicitly(self):
        """The engine defaults to two hours when no expiry is sent.

        Ticket.expiry is a time to live in seconds, so the requested
        lifetime is sent as is, not added to the current time.
        """
        src, sdk, types, _, console_service = self._source(
            granted=_Granted('a-ticket', 90))

        self._mint(src, sdk, types, lifetime=90)

        types.Ticket.assert_called_once_with(expiry=90)
        console_service.ticket.assert_called_once_with(
            ticket=types.Ticket.return_value)

    def test_get_console_for_vm_reports_value_and_granted_ttl(self):
        connection, console_service = _console_connection(
            [_Console('vnc'), _Console('spice')],
            granted=_Granted('a-ticket', 75))
        src, sdk, types = _make_source(connection)

        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types):
            console, ticket, ttl = src.get_console_for_vm(
                'vm-1', ticket_lifetime=75.9)

        self.assertEqual('console-spice', console.id)
        self.assertEqual('a-ticket', ticket)
        self.assertEqual(75, ttl)
        types.Ticket.assert_called_once_with(expiry=75)

    def test_get_console_for_vm_without_lifetime_mints_nothing(self):
        connection, console_service = _console_connection(
            [_Console('spice')])
        src, sdk, types = _make_source(connection)

        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types):
            console, ticket, ttl = src.get_console_for_vm('vm-1')

        self.assertEqual('console-spice', console.id)
        self.assertIsNone(ticket)
        self.assertIsNone(ttl)
        console_service.ticket.assert_not_called()

    def test_get_console_for_vm_leaves_a_passed_connection_open(self):
        src, sdk, types, connection, _ = self._source(
            granted=_Granted('a-ticket', 90))

        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types):
            src.get_console_for_vm(
                'vm-1', connection=connection, ticket_lifetime=90)

        connection.close.assert_not_called()
        sdk.Connection.assert_not_called()

    def test_mint_returns_now_plus_granted_ttl(self):
        src, sdk, types, _, _ = self._source(
            granted=_Granted('a-ticket', 90))

        minted = self._mint(src, sdk, types, lifetime=90)

        self.assertIsInstance(minted, base.MintedTicket)
        self.assertEqual('a-ticket', minted.ticket)
        self.assertEqual(int(self.NOW) + 90, minted.expires)

    def test_mint_reports_a_shorter_granted_ttl(self):
        src, sdk, types, _, _ = self._source(
            granted=_Granted('a-ticket', 30))

        minted = self._mint(src, sdk, types, lifetime=90)

        types.Ticket.assert_called_once_with(expiry=90)
        self.assertEqual(int(self.NOW) + 30, minted.expires)

    def test_mint_falls_back_to_requested_lifetime_without_expiry(self):
        src, sdk, types, _, _ = self._source(
            granted=_Granted('a-ticket', None))

        minted = self._mint(src, sdk, types, lifetime=90)

        self.assertEqual(int(self.NOW) + 90, minted.expires)

    def test_mint_closes_the_connection_it_opened(self):
        src, sdk, types, connection, _ = self._source(
            granted=_Granted('a-ticket', 90))

        self._mint(src, sdk, types)

        sdk.Connection.assert_called_once()
        connection.close.assert_called_once_with()

    def test_mint_raises_when_the_source_errored_at_init(self):
        src, sdk, types, _, _ = self._source(ca_status=500)
        self.assertTrue(src.errored)

        with self.assertRaises(base.ConsoleTicketUnavailable):
            self._mint(src, sdk, types)
        sdk.Connection.assert_not_called()

    def test_mint_raises_without_a_spice_console(self):
        src, sdk, types, connection, console_service = self._source(
            consoles=[_Console('vnc')])

        with self.assertRaises(base.ConsoleTicketUnavailable):
            self._mint(src, sdk, types)
        console_service.ticket.assert_not_called()
        connection.close.assert_called_once_with()

    def test_mint_raises_when_the_ticket_call_fails(self):
        class EngineError(Exception):
            pass

        src, sdk, types, connection, _ = self._source(
            ticket_error=EngineError('engine said no'))

        with self.assertRaises(EngineError):
            self._mint(src, sdk, types)
        connection.close.assert_called_once_with()

    def test_mint_raises_when_the_engine_returns_no_ticket(self):
        src, sdk, types, connection, _ = self._source(
            granted=_Granted(None, None))

        with self.assertRaises(base.ConsoleTicketUnavailable):
            self._mint(src, sdk, types)
        connection.close.assert_called_once_with()


class TestOVirtTimeouts(unittest.TestCase):
    """Every request to the engine is bounded by MINT_TIMEOUT.

    ovirtsdk4 is not installed in the unit test environment, so the SDK's
    own handling of timeout (it sets pycurl.TIMEOUT on the handle every API
    request, the ticket action included, is sent on) cannot be exercised
    here. These tests assert the timeout is passed to it. The CA fetch goes
    through requests, which is installed, so it is also tested against a
    server which accepts a connection and never answers.
    """

    def test_ca_fetch_and_connection_are_given_the_timeout(self):
        connection, _ = _console_connection(
            [_Console('spice')], granted=_Granted('a-ticket', 90))
        src, sdk, types = _make_source(connection)

        self.assertEqual(
            ovirt_source.MINT_TIMEOUT,
            src.ca_get.call_args.kwargs['timeout'])

        with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
                mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types):
            src.mint_console_ticket('vm-1', 90)

        self.assertEqual(
            ovirt_source.MINT_TIMEOUT,
            sdk.Connection.call_args.kwargs['timeout'])

    def test_a_ca_fetch_error_marks_the_source_errored(self):
        with mock.patch.object(ovirt_source, 'OVIRT_SDK', mock.Mock()), \
                mock.patch.object(ovirt_source.requests, 'get',
                                  side_effect=requests.exceptions.Timeout()):
            src = ovirt_source.oVirtSource(
                source='test-ovirt', type='ovirt',
                url='https://ovirt.example.com/ovirt-engine',
                username='admin@ovirt@internalsso', password='secret',
                ca_cert='CACERT', ca_file='/dev/null')

        self.assertTrue(src.errored)

    def test_a_stalled_engine_fails_the_ca_fetch_promptly(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        accepted = []

        def accept_and_stall():
            try:
                conn, _ = listener.accept()
                accepted.append(conn)
            except OSError:
                pass

        stall = threading.Thread(target=accept_and_stall, daemon=True)
        stall.start()

        # The construction runs in a thread so that a missing timeout fails
        # this test rather than hanging the suite.
        built = []

        def construct():
            with mock.patch.object(ovirt_source, 'OVIRT_SDK', mock.Mock()):
                built.append(ovirt_source.oVirtSource(
                    source='test-ovirt', type='ovirt',
                    url='http://127.0.0.1:%d/ovirt-engine'
                    % listener.getsockname()[1],
                    username='admin@ovirt@internalsso', password='secret',
                    ca_cert='CACERT', ca_file='/dev/null'))

        with mock.patch.object(ovirt_source, 'MINT_TIMEOUT', 0.5):
            builder = threading.Thread(target=construct, daemon=True)
            builder.start()
            builder.join(5)
            finished = not builder.is_alive()

        # Release a fetch which is still waiting, so the thread ends.
        for conn in accepted:
            conn.close()
        builder.join(5)

        self.assertTrue(finished, 'the CA fetch did not time out')
        self.assertTrue(built[0].errored)
