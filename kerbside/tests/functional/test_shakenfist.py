import requests
from shakenfist_client import apiclient as sf_apiclient
from shakenfist_utilities import random as sf_random
import testtools
import time


from .. import spiceprotocol


class ShakenFistTestCase(testtools.TestCase):
    def setUp(self):
        super(ShakenFistTestCase, self).setUp()

        # Create a new namespace for this test
        self.namespace = 'kerbside-test-%s' % sf_random.random_id()
        key = sf_random.random_id()

        self.system_client = sf_apiclient.Client(
            async_strategy=sf_apiclient.ASYNC_PAUSE)
        self.system_client.create_namespace(self.namespace)
        self.system_client.add_namespace_key(self.namespace, 'test', key)
        self.system_client.add_namespace_trust('ci-images', self.namespace)

        # Cache the required image in the shared ci-images namespace to avoid
        # repeated downloads
        self.system_client.cache_artifact('debian-gnome:11', namespace='ci-images')

        # Create a client for the namespace
        self.namespace_client = sf_apiclient.Client(
            base_url=self.system_client.base_url,
            namespace=self.namespace, key=key,
            async_strategy=sf_apiclient.ASYNC_PAUSE)

        # Create an instance in that namespace
        self.instance = self.namespace_client.create_instance(
            'kerbside-target', 2, 2048, None,
            [
                {
                    'size': 50,
                    'base': 'debian-gnome:11',
                    'type': 'disk'
                }
            ], None, None,
            video={
                'model': 'qxl',
                'memory': 65536,
                'vdi': 'spice'
            }
        )

        # Wait for the instance to start
        start_time = time.time()
        while time.time() - start_time < 300:
            self.instance = self.namespace_client.get_instance(
                self.instance['uuid'])
            if self.instance['state'] == 'error':
                break

            if (self.instance['agent_state'] and
                    self.instance['agent_state'].startswith('ready')):
                break
            time.sleep(5)

    def tearDown(self):
        super(ShakenFistTestCase, self).tearDown()

        if self.instance:
            self.system_client.delete_instance(self.instance['uuid'])
        self.system_client.remove_namespace_trust('ci-images', self.namespace)
        self.system_client.delete_namespace(self.namespace)


class ShakenFistDirectVirtViewerTests(ShakenFistTestCase):
    def test_connect(self):
        # Make sure the target instance came up correctly
        if (self.instance['agent_state'] and
                not self.instance['agent_state'].startswith('ready')):
            self.fail(
                'Instance %s failed to start and enter the agent ready state '
                'during setUp(). Agent state is %s.'
                % (self.instance['uuid'], self.instance['agent_state']))

        # Fetch the virt viewer configuration for the instance from Shaken Fist
        vv = self.namespace_client.get_vdi_console_helper(self.instance['uuid'])

        # Construct a SPICE client from that config
        sc = spiceprotocol.SpiceClient()
        sc.from_vv_file(vvconfig=vv)
        sc.connect()


class ShakenFistProxyVirtViewerTests(ShakenFistTestCase):
    def test_connect(self):
        # Make sure the target instance came up correctly
        if (self.instance['agent_state'] and
                not self.instance['agent_state'].startswith('ready')):
            self.fail(
                'Instance %s failed to start and enter the agent ready state '
                'during setUp(). Agent state is %s.'
                % (self.instance['uuid'], self.instance['agent_state']))

        # Fetch the virt viewer configuration for the instance from the proxy
        url = ('http://kerbside.home.stillhq.com:13002/console/proxy/'
               'sfcbr/%s/console.vv' % self.instance['uuid'])

        # It can take up to a minute for the console to appear with the proxy
        start_time = time.time()
        while time.time() - start_time < 90:
            r = requests.get(url)
            if r.status_code == 200:
                vv = r.text
                break
            time.sleep(30)

        if time.time() - start_time > 89:
            self.fail('Console for %s never appeared in the proxy'
                      % self.instance['uuid'])

        # Construct a SPICE client from that config
        sc = spiceprotocol.SpiceClient()
        sc.from_vv_file(vvconfig=vv)
        sc.connect()
