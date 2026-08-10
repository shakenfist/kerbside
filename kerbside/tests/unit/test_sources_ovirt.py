import unittest
from unittest import mock

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


def _make_source(connection):
    """Build an oVirtSource with the SDK and the CA check stubbed out."""
    sdk = mock.Mock()
    sdk.Connection.return_value = connection
    types = mock.Mock()
    types.GraphicsType.SPICE = 'spice'

    with mock.patch.object(ovirt_source, 'OVIRT_SDK', sdk), \
            mock.patch.object(ovirt_source, 'OVIRT_SDK_TYPES', types), \
            mock.patch.object(ovirt_source.requests, 'get') as mock_get:
        mock_get.return_value = mock.Mock(status_code=200, text='CACERT')
        src = ovirt_source.oVirtSource(
            source='test-ovirt', type='ovirt',
            url='https://ovirt.example.com/ovirt-engine',
            username='admin@ovirt@internalsso', password='secret',
            ca_cert='CACERT', ca_file='/dev/null')
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
