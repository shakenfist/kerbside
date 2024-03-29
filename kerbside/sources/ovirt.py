import importlib
import os
import requests
from shakenfist_utilities import logs
import tempfile

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


OVIRT_SDK = None
OVIRT_SDK_TYPES = None


class oVirtSource(base.BaseSource):
    def __init__(self, **kwargs):
        global OVIRT_SDK
        global OVIRT_SDK_TYPES

        self.args = kwargs
        self.discovered_ca_cert = None
        self.errored = False
        self.ca_tempfile = None

        if not OVIRT_SDK:
            try:
                OVIRT_SDK = importlib.import_module('ovirtsdk4')
                OVIRT_SDK_TYPES = importlib.import_module('ovirtsdk4.types')
            except Exception as e:
                LOG.error('Failed to import oVirt client: %s' % e)
                self.errored = True
                return

        # Annoyingly, our CA certificate must exist on disk
        if 'ca_file' not in self.args:
            fd, self.ca_tempfile = tempfile.mkstemp()
            os.close(fd)
            with open(self.ca_tempfile, 'w') as f:
                f.write(self.args['ca_cert'])
            self.args['ca_file'] = self.ca_tempfile

        # Fetch the engine CA certificate
        r = requests.get(
            '%s/services/pki-resource?resource=ca-certificate&format=X509-PEM-CA'
            % self.args['url'], verify=self.args['ca_file'])
        if r.status_code != 200:
            LOG.warning('Ignoring source %s due to missing CA certificate from engine.'
                        % self.args['source'])
            self.errored = True
            return
        self.discovered_ca_cert = r.text

        # Check we agree on CA certificates
        if self.discovered_ca_cert.rstrip() != self.args['ca_cert'].rstrip():
            LOG.warning('CA certificate verification failed for source %s.'
                        % self.args['source'])
            LOG.warning('Discovered: %s' % self.discovered_ca_cert.replace('\n', '\\n'))
            LOG.warning('Configured: %s' % self.args['ca_cert'].replace('\n', '\\n'))
            self.errored = True
            return

    def _ensure_connection(self, connection):
        if not connection:
            connection = OVIRT_SDK.Connection(
                url=self.args['url'] + '/api',
                username=self.args['username'],
                password=self.args['password'],
                ca_file=self.args['ca_file'],
                debug=False,
                log=LOG,
            )
        return connection

    def __call__(self):
        global OVIRT_SDK
        if not OVIRT_SDK:
            LOG.warning('Ignoring source %s due to missing ovirt-engine-sdk4.'
                        % self.args['source'])
            return

        host_cache = {}

        connection = self._ensure_connection(None)
        vms_service = connection.system_service().vms_service()
        hosts_service = connection.system_service().hosts_service()

        for vm in vms_service.list():
            log = LOG.with_fields({
                    'id': vm.id,
                    'status': vm.status
                    })

            if str(vm.status) != 'up':
                log.debug('Ignoring instance with incorrect status')
                continue

            if vm.host.id and vm.host.id not in host_cache:
                host = hosts_service.list(search='id=%s' % vm.host.id)[0]
                host_cache[host.id] = host.certificate.subject

            console, _ = self.get_console_for_vm(
                vm.id, connection=connection, acquire_ticket=False)
            if not console:
                log.debug('Ignoring instance with no SPICE console.')

            yield {
                'uuid': vm.id,
                'source': self.args['source'],
                'hypervisor': '',
                'hypervisor_ip': console.address,
                'insecure_port': console.port,
                'secure_port': console.tls_port,
                'name': '%s' % vm.name,
                'host_subject': host_cache.get(vm.host.id)
            }

        # Close the connection to the server:
        connection.close()

    def close(self):
        if self.ca_tempfile:
            os.unlink(self.ca_tempfile)

    def get_console_for_vm(self, id, connection=None, acquire_ticket=False):
        connection = self._ensure_connection(connection)
        vms_service = connection.system_service().vms_service()
        vm_service = vms_service.vm_service(id)
        consoles_service = vm_service.graphics_consoles_service()

        # The method that lists the graphics consoles doesn't support search, so in
        # order to find the console corresponding to the access protocol that we are
        # interested in (SPICE in this example) we need to get all of them and filter
        # explicitly. In addition the `current` parameter must be `True`, as otherwise
        # you will *not* get important values like the `address` and `port` where the
        # console is available.
        consoles = consoles_service.list(current=True)
        console = next(
            (c for c in consoles if c.protocol == OVIRT_SDK_TYPES.GraphicsType.SPICE),
            None
        )

        ticket = None
        if console and acquire_ticket:
            console_service = consoles_service.console_service(console.id)
            ticket = console_service.ticket().value

        return console, ticket
