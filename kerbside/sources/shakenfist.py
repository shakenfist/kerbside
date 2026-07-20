import importlib
import json
import time
import yaml
from shakenfist_utilities import logs

from . import base
from .. import db
from ..config import config
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


SHAKENFIST_CLIENT = None


def _build_client(source_args, namespace):
    return SHAKENFIST_CLIENT.Client(
        base_url=source_args['url'], namespace=namespace,
        key=source_args['password'],
        async_strategy=SHAKENFIST_CLIENT.ASYNC_BLOCK)


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

        # Cache the cluster's VDI token signing public keys so offline
        # console-token verification never has to call Shaken Fist on the
        # hot path. A transient fetch failure must not crash source
        # construction; mark the source errored and log, mirroring the CA
        # certificate handling above.
        try:
            self.fetch_signing_keys()
        except Exception as e:
            LOG.warning('Failed to fetch signing keys for source %s: %s'
                        % (self.args['source'], e))
            self.errored = True
            return

    def _make_client(self, namespace):
        return _build_client(self.args, namespace)

    def fetch_signing_keys(self):
        # Fetch this cluster's VDI token signing public keys and cache them
        # in the DB for offline JWT verification. Symmetric with the
        # get_cluster_cacert() fetch above.
        keys = self._make_client('system').get_vdi_token_public_keys()
        db.upsert_sf_token_keys(
            self.args['source'], json.dumps(keys), time.time())

    def __call__(self):
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


def refresh_all_signing_keys():
    """Refetch and cache every shakenfist source's signing keys.

    This is the rotation / refetch-once path that
    sf_token.verify_sf_token invokes when it sees an unknown kid; it is the
    only place console-token verification touches Shaken Fist. A per-source
    failure is logged and skipped so one unreachable cluster cannot block
    refreshing the others.
    """
    global SHAKENFIST_CLIENT
    if not SHAKENFIST_CLIENT:
        try:
            SHAKENFIST_CLIENT = importlib.import_module(
                'shakenfist_client.apiclient')
        except Exception as e:
            LOG.error('Failed to import Shaken Fist client: %s' % e)
            return

    with open(config.SOURCES_PATH) as f:
        sources = yaml.safe_load(f) or []

    for source in sources:
        if source.get('type') != 'shakenfist':
            continue
        try:
            keys = _build_client(source, 'system').get_vdi_token_public_keys()
            db.upsert_sf_token_keys(
                source['source'], json.dumps(keys), time.time())
        except Exception as e:
            LOG.warning('Failed to refresh signing keys for source %s: %s'
                        % (source.get('source'), e))
