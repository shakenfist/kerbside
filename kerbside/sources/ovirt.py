import importlib
import os
import requests
from shakenfist_utilities import logs
import tempfile
import time

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


OVIRT_SDK = None
OVIRT_SDK_TYPES = None

# Seconds to wait for any one request to the engine: the CA certificate fetch,
# and each API call on an SDK connection. A console ticket is minted while a
# client waits to connect, so a stalled engine has to fail the request rather
# than hold it indefinitely.
MINT_TIMEOUT = 15


class oVirtSource(base.BaseSource):
    MINTS_TICKETS = True

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

        # Fetch the engine CA certificate. An engine which cannot be reached
        # is reported as an errored source, as a missing certificate is, so
        # that the caller still gets an object it can close().
        try:
            r = requests.get(
                '%s/services/pki-resource?resource=ca-certificate&format=X509-PEM-CA'
                % self.args['url'], verify=self.args['ca_file'],
                timeout=MINT_TIMEOUT)
        except requests.exceptions.RequestException as e:
            LOG.warning('Ignoring source %s as its engine CA certificate could not be '
                        'fetched: %s' % (self.args['source'], type(e).__name__))
            self.errored = True
            return
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
        # The SDK applies timeout to each API request, the ticket action
        # included. It does not apply it to the SSO login the connection
        # performs before its first request, which runs on a separate curl
        # handle with no timeout, so a caller which must bound a whole mint
        # needs a deadline of its own around it.
        if not connection:
            connection = OVIRT_SDK.Connection(
                url=self.args['url'] + '/api',
                username=self.args['username'],
                password=self.args['password'],
                ca_file=self.args['ca_file'],
                debug=False,
                log=LOG,
                timeout=MINT_TIMEOUT,
            )
        return connection

    def __call__(self):
        if not OVIRT_SDK:
            LOG.warning('Ignoring source %s due to missing ovirt-engine-sdk4.'
                        % self.args['source'])
            return

        connection = self._ensure_connection(None)
        try:
            yield from self._discover(connection)
        finally:
            connection.close()

    def _discover(self, connection):
        host_cache = {}
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

            console, _, _ = self.get_console_for_vm(vm.id, connection=connection)
            if not console:
                log.debug('Ignoring instance with no SPICE console.')
                continue

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

    def close(self):
        if self.ca_tempfile:
            os.unlink(self.ca_tempfile)

    def get_console_for_vm(self, id, connection=None, ticket_lifetime=None):
        """Find a VM's SPICE console, and optionally mint a ticket for it.

        Returns (console, ticket, ticket_ttl). console is None if the VM has
        no SPICE console. If ticket_lifetime is set, a ticket valid for that
        many seconds is requested, and ticket and ticket_ttl are its value
        and the lifetime in seconds the engine granted; otherwise both are
        None. A connection opened here is closed before returning; one passed
        in is left open for its owner.
        """
        if connection:
            return self._get_console_for_vm(id, connection, ticket_lifetime)

        connection = self._ensure_connection(None)
        try:
            return self._get_console_for_vm(id, connection, ticket_lifetime)
        finally:
            connection.close()

    def _get_console_for_vm(self, id, connection, ticket_lifetime):
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

        if not console or ticket_lifetime is None:
            return console, None, None

        # Ticket.expiry is a time to live in seconds, not a timestamp. The
        # engine uses two hours if none is requested, so one always is. Its
        # response echoes the value and expiry it applied.
        console_service = consoles_service.console_service(console.id)
        granted = console_service.ticket(
            ticket=OVIRT_SDK_TYPES.Ticket(expiry=int(ticket_lifetime)))
        if not granted or not granted.value:
            return console, None, None

        # An engine which leaves expiry out of its response applied what was
        # asked for, so report the requested lifetime in that case.
        ttl = granted.expiry
        if ttl is None:
            ttl = int(ticket_lifetime)
        return console, granted.value, int(ttl)

    def mint_console_ticket(self, uuid, lifetime):
        if self.errored or not OVIRT_SDK:
            raise base.ConsoleTicketUnavailable(
                'source %s is not usable' % self.args.get('source'))

        # The time is taken before the request, so that the expiry reported
        # is never later than the one the engine applies.
        now = int(time.time())
        console, ticket, ttl = self.get_console_for_vm(uuid, ticket_lifetime=lifetime)
        if not console:
            raise base.ConsoleTicketUnavailable(
                'VM %s has no SPICE console' % uuid)
        if not ticket:
            raise base.ConsoleTicketUnavailable(
                'the engine returned no ticket for VM %s' % uuid)
        return base.MintedTicket(ticket, now + ttl)
