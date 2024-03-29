import importlib
from keystoneauth1.identity import v3
from keystoneauth1 import session
from openstack import connection
from shakenfist_utilities import logs

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


OPENSTACK_CLIENT = None


class OpenStackSource(base.BaseSource):
    def __init__(self, **kwargs):
        global OPENSTACK_CLIENT

        self.args = kwargs
        self.discovered_ca_cert = None
        self.errored = False

        if not OPENSTACK_CLIENT:
            try:
                # TODO(mikal): this is wrong, we need to import the auth
                # stuff here as well, and then actually use OPENSTACK_CLIENT.
                OPENSTACK_CLIENT = importlib.import_module('openstack')
            except Exception as e:
                LOG.error('Failed to import OpenStack client: %s' % e)
                self.errored = True
                return

    def _make_client(self):
        global OPENSTACK_CLIENT

        auth = v3.Password(
            auth_url=self.args['url'],
            username=self.args['username'],
            password=self.args['password'],
            project_name=self.args['project_name'],
            user_domain_id=self.args['user_domain_id'],
            project_domain_id=self.args['project_domain_id'])
        return connection.Connection(session=session.Session(auth=auth))

    def __call__(self):
        global OPENSTACK_CLIENT
        if not OPENSTACK_CLIENT:
            LOG.warning('Ignoring source %s due to missing openstack client.'
                        % self.args['source'])
            return

        conn = self._make_client()
        for inst in conn.list_servers():
            log = LOG.with_fields({
                'id': inst['id'],
                'status': inst['status'],
                'flavor': inst['flavor']['original_name']
                })

            if inst['status'] != 'ACTIVE':
                log.debug('Ignoring instance with incorrect status')
                continue

            if inst['flavor']['original_name'] not in self.args.get('flavor'):
                log.debug('Ignoring instance with incorrect flavor')
                continue

            console_data = conn.compute.create_console(
                inst['id'], console_type='spice-direct')
            if 'port' not in console_data or not console_data['port']:
                log.debug('Ignoring instance with not allocated SPICE port')
                continue

            yield {
                'uuid': inst['id'],
                'source': self.args['source'],
                'hypervisor': inst['OS-EXT-SRV-ATTR:hypervisor_hostname'],
                'hypervisor_ip': console_data['host'],
                'insecure_port': console_data['port'],
                'secure_port': console_data['tls_port'],
                'name': inst['name'],
                'host_subject': None
            }
