import importlib
from shakenfist_utilities import logs

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


SHAKENFIST_CLIENT = None


class ShakenFistSource(base.BaseSource):
    def __init__(self, **kwargs):
        global SHAKENFIST_CLIENT

        self.args = kwargs
        self.discovered_ca_cert = None
        self.errored = False

        if not SHAKENFIST_CLIENT:
            try:
                SHAKENFIST_CLIENT = importlib.import_module(
                    'shakenfist_client.apiclient')
            except Exception as e:
                LOG.error('Failed to import Shaken Fist client: %s' % e)
                self.errored = True
                return

        # Fetch the cluster CA certificate
        system_client = self._make_client('system')
        self.discovered_ca_cert = system_client.get_cluster_cacert()

        # Check we agree on CA certificates
        if self.discovered_ca_cert.rstrip() != self.args['ca_cert'].rstrip():
            LOG.warning('CA certificate verification failed for source %s.'
                        % self.args['source'])
            LOG.warning('Discovered: %s' % self.discovered_ca_cert.replace('\n', '\\n'))
            LOG.warning('Configured: %s' % self.args['ca_cert'].replace('\n', '\\n'))
            self.errored = True
            return

    def _make_client(self, namespace):
        global SHAKENFIST_CLIENT
        return SHAKENFIST_CLIENT.Client(
            base_url=self.args['url'], namespace=namespace, key=self.args['password'],
            async_strategy=SHAKENFIST_CLIENT.ASYNC_BLOCK)

    def __call__(self):
        global SHAKENFIST_CLIENT
        if not SHAKENFIST_CLIENT:
            LOG.warning('Ignoring source %s due to missing shakenfist-client.'
                        % self.args['source'])
            return

        # We need to be an admin user to lookup the hypervisors
        system_client = self._make_client('system')
        nodes = {}
        for node in system_client.get_nodes():
            nodes[node['name']] = node

        # And then just lookup instances in the right namespace
        namespaced_client = self._make_client(self.args['username'])
        for inst in namespaced_client.get_instances():
            log = LOG.with_fields({
                    'uuid': inst['uuid'],
                    'state': inst['state'],
                    'video': inst['video']
                    })

            if inst['state'] != 'created':
                log.debug('Ignoring instance in incorrect state')
                continue
            if not inst['video']['vdi'].startswith('spice'):
                log.debug('Ignoring instance with incorrect VDI type')
                continue

            yield {
                'uuid': inst['uuid'],
                'source': self.args['source'],
                'hypervisor': inst['node'],
                'hypervisor_ip': nodes[inst['node']]['ip'],
                'insecure_port': inst['vdi_port'],
                'secure_port': inst['vdi_tls_port'],
                'name': '%s.%s' % (inst['name'], inst['namespace']),
                'host_subject': None
            }
